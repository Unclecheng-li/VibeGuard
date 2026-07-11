import type { Finding, L3AnalyzerLike, Severity, SourceFile } from "../types";
import { createFinding, positionAt } from "../utils";

interface EndpointCandidate {
  kind: "javascript" | "python" | "java";
  method: string;
  path: string;
  index: number;
  endIndex: number;
  snippet: string;
}

interface SemanticRuleResult {
  ruleId: string;
  severity: Severity;
  message: string;
  suggestion: string;
}

export interface SecurityReviewContext {
  framework: string;
  functionNames: string[];
  routes: string[];
  globalControls: string[];
}

export interface SecurityReviewTarget {
  functionName?: string;
  route: string;
  startLine: number;
  code: string;
}

export class LocalSemanticAnalyzer implements L3AnalyzerLike {
  analyze(source: SourceFile, timestamp: number): Finding[] {
    return analyzeSecurityDimensions(source, timestamp);
  }
}

export function analyzeSecurityDimensions(source: SourceFile, timestamp: number): Finding[] {
  const candidates = [
    ...findJavaScriptEndpoints(source.text),
    ...findPythonEndpoints(source.text),
    ...findDjangoEndpoints(source.text),
    ...findJavaEndpoints(source.text)
  ];
  const middlewareControls = detectJavaScriptMiddlewareControls(source.text);
  const findings: Finding[] = [];

  for (const candidate of candidates) {
    const rules = evaluateEndpoint(candidate, middlewareControls);
    for (const rule of rules) {
      findings.push(
        createFinding({
          type: "missing_security_measure",
          severity: rule.severity,
          message: rule.message,
          file: source.filePath,
          index: candidate.index,
          endIndex: candidate.endIndex,
          text: source.text,
          evidence: candidate.snippet,
          suggestion: rule.suggestion,
          detectionLayer: "L3",
          ruleId: rule.ruleId,
          timestamp
        })
      );
    }
  }

  return findings;
}

export function buildSecurityReviewPrompt(source: SourceFile, code: string): string {
  const context = buildSecurityReviewContext(source);
  return [
    "Analyze this function and check if it's missing critical security measures.",
    "",
    "Function code:",
    code,
    "",
    "Function context:",
    `- File: ${source.filePath}`,
    `- Language: ${source.languageId ?? "unknown"}`,
    `- Framework: ${context.framework}`,
    `- Functions: ${formatContextValues(context.functionNames)}`,
    `- Routes: ${formatContextValues(context.routes)}`,
    `- Global middleware controls: ${formatContextValues(context.globalControls)}`,
    "",
    "Check for missing:",
    "1. Input validation (if accepts user input)",
    "2. Rate limiting (if is an API endpoint)",
    "3. Parameterized queries (if touches database)",
    "4. Error handling (if performs IO)",
    "5. Authentication (if accesses sensitive data)",
    "6. Output encoding (if returns HTML)",
    "",
    "Return JSON with missing, severity, and suggestion."
  ].join("\n");
}

export function buildSecurityReviewContext(source: SourceFile): SecurityReviewContext {
  return {
    framework: detectFramework(source),
    functionNames: detectedFunctionNames(source.text),
    routes: detectedRoutes(source.text),
    globalControls: describeMiddlewareControls(detectJavaScriptMiddlewareControls(source.text))
  };
}

/**
 * Selects route-handler bodies for L3 so an LLM sees the executable security
 * boundary instead of losing it to a large-file prefix truncation.
 */
export function buildSecurityReviewTargets(source: SourceFile): SecurityReviewTarget[] {
  const candidates = [
    ...findJavaScriptEndpoints(source.text),
    ...findPythonEndpoints(source.text),
    ...findDjangoEndpoints(source.text),
    ...findJavaEndpoints(source.text)
  ].sort((left, right) => left.index - right.index || left.endIndex - right.endIndex);
  const seen = new Set<string>();

  return candidates
    .filter((candidate) => {
      const key = `${candidate.index}:${candidate.endIndex}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .slice(0, 6)
    .map((candidate) => ({
      functionName: detectedFunctionNames(candidate.snippet)[0],
      route: `${candidate.method.toUpperCase()} ${candidate.path}`,
      startLine: positionAt(source.text, candidate.index).line,
      code: candidate.snippet
    }));
}

function detectFramework(source: SourceFile): string {
  const text = source.text;
  if (/\borg\.springframework\b|\bSpringApplication\b|@(?:Rest)?Controller\b|@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b/.test(text)) {
    return "Spring";
  }
  if (/\b(?:from\s+fastapi\s+import|FastAPI\s*\()/i.test(text)) {
    return "FastAPI";
  }
  if (/\b(?:from\s+flask\s+import|Flask\s*\(|Blueprint\s*\()/i.test(text)) {
    return "Flask";
  }
  if (/\b(?:django|urlpatterns|path\s*\()/i.test(text)) {
    return "Django";
  }
  if (/\b(?:@nestjs|NestFactory)\b/i.test(text)) {
    return "NestJS";
  }
  if (/\b(?:from\s+['"]express['"]|require\s*\(\s*['"]express['"]\s*\)|express\s*\()/i.test(text)) {
    return "Express";
  }
  if (/\b(?:from\s+['"]koa['"]|require\s*\(\s*['"]koa['"]\s*\)|new\s+Koa\s*\()/i.test(text)) {
    return "Koa";
  }
  if (source.languageId === "typescriptreact" || /<\s*[A-Z][A-Za-z0-9]*/.test(text)) {
    return "React";
  }
  return "Unknown";
}

function detectedFunctionNames(text: string): string[] {
  const names = new Set<string>();
  const patterns = [
    /\b(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>/g,
    /\b(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g,
    /\b(?:public|protected|private)\s+(?:static\s+)?[A-Za-z_$][A-Za-z0-9_$<>, ?\[\].]*\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      if (match[1]) {
        names.add(match[1]);
      }
    }
  }
  return [...names].slice(0, 12);
}

function detectedRoutes(text: string): string[] {
  const routes = new Set<string>();
  const patterns = [
    /\b(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    /@(?:app|router|blueprint)\.(route|get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/gi
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const method = match[1]?.toUpperCase() ?? "ROUTE";
      const path = match[2];
      if (path) {
        routes.add(`${method} ${path}`);
      }
    }
  }
  for (const endpoint of findJavaEndpoints(text)) {
    routes.add(`${endpoint.method.toUpperCase()} ${endpoint.path}`);
  }
  for (const endpoint of findDjangoEndpoints(text)) {
    routes.add(`${endpoint.method.toUpperCase()} ${endpoint.path}`);
  }
  return [...routes].slice(0, 12);
}

function formatContextValues(values: readonly string[]): string {
  return values.length > 0 ? values.join(", ") : "Not confidently detected";
}

function findJavaScriptEndpoints(text: string): EndpointCandidate[] {
  const endpoints: EndpointCandidate[] = [];
  const routeRegex =
    /\b(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`][\s\S]{0,900}?\{[\s\S]{0,1800}?\n\s*\}\s*\)?\s*;?/gi;

  for (const match of text.matchAll(routeRegex)) {
    const index = match.index ?? 0;
    const snippet = match[0];
    endpoints.push({
      kind: "javascript",
      method: (match[1] ?? "").toLowerCase(),
      path: match[2] ?? "",
      index,
      endIndex: index + snippet.length,
      snippet
    });
  }

  return endpoints;
}

function findPythonEndpoints(text: string): EndpointCandidate[] {
  const endpoints: EndpointCandidate[] = [];
  const routeRegex =
    /@(?:app|router|blueprint)\.(?:route|get|post|put|patch|delete)\s*\(\s*["']([^"']+)["'][^\n]*\)\s*\n(?:@[^\n]+\n)*\s*(?:async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*:\s*\n(?:[ \t]+[^\n]*\n?){1,80}/g;

  for (const match of text.matchAll(routeRegex)) {
    const decorator = match[0].split("\n")[0] ?? "";
    const method = decorator.match(/\.(route|get|post|put|patch|delete)\s*\(/i)?.[1]?.toLowerCase() ?? inferPythonRouteMethod(decorator);
    const index = match.index ?? 0;
    const snippet = match[0];
    endpoints.push({
      kind: "python",
      method,
      path: match[1] ?? "",
      index,
      endIndex: index + snippet.length,
      snippet
    });
  }

  return endpoints;
}

function findDjangoEndpoints(text: string): EndpointCandidate[] {
  if (!/\b(?:django|JsonResponse|HttpResponse|StreamingHttpResponse|api_view|login_required|permission_required)\b/i.test(text)) {
    return [];
  }

  const endpoints: EndpointCandidate[] = [];
  const views = findDjangoFunctionViews(text);
  const viewsByName = new Map(views.map((view) => [view.name, view]));
  const selectedViews = new Set<number>();
  const routeRegex = /\b(?:path|re_path)\s*\(\s*r?["']([^"']+)["']\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\b/g;

  for (const routeMatch of text.matchAll(routeRegex)) {
    const path = normalizeDjangoPath(routeMatch[1] ?? "");
    const viewName = routeMatch[2] ?? "";
    const view = viewsByName.get(viewName);
    if (!path || !view || selectedViews.has(view.index)) {
      continue;
    }
    selectedViews.add(view.index);
    endpoints.push({
      kind: "python",
      method: inferDjangoRouteMethod(view.snippet),
      path,
      index: view.index,
      endIndex: view.index + view.snippet.length,
      snippet: view.snippet
    });
  }

  // Django commonly keeps urlpatterns in urls.py and the function views in
  // views.py. A request-first function that returns a framework response is a
  // useful, conservative endpoint candidate even without its route file.
  for (const view of views) {
    if (selectedViews.has(view.index) || !isDjangoResponseView(view.snippet)) {
      continue;
    }
    endpoints.push({
      kind: "python",
      method: inferDjangoRouteMethod(view.snippet),
      path: `/${view.name.replace(/_/g, "-")}`,
      index: view.index,
      endIndex: view.index + view.snippet.length,
      snippet: view.snippet
    });
  }

  return endpoints;
}

interface DjangoFunctionView {
  name: string;
  index: number;
  snippet: string;
}

function findDjangoFunctionViews(text: string): DjangoFunctionView[] {
  const views: DjangoFunctionView[] = [];
  const functionRegex =
    /(?:^[\t ]*@[^\r\n]+\r?\n)*^[\t ]*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*request(?:\s*:[^,)=]+)?(?:\s*=[^,)]+)?(?:\s*,[^\r\n)]*)?\)\s*(?:->[^:\r\n]+)?\s*:\s*(?:\r?\n|$)(?:^[\t ]+[^\r\n]*(?:\r?\n|$)|^\s*(?:\r?\n|$)){0,80}/gm;

  for (const match of text.matchAll(functionRegex)) {
    const name = match[1];
    const snippet = match[0];
    if (name && snippet) {
      views.push({ name, index: match.index ?? 0, snippet });
    }
  }
  return views;
}

function isDjangoResponseView(snippet: string): boolean {
  return /\b(?:JsonResponse|HttpResponse|StreamingHttpResponse|Response|render|redirect)\s*\(|@api_view\b/.test(snippet);
}

function normalizeDjangoPath(path: string): string {
  const withoutRegexAnchors = path.replace(/^\^/, "").replace(/\$$/, "");
  return withoutRegexAnchors.startsWith("/") ? withoutRegexAnchors : `/${withoutRegexAnchors}`;
}

function inferDjangoRouteMethod(snippet: string): string {
  const direct = snippet.match(/@require_(GET|POST|PUT|PATCH|DELETE)\b/i)?.[1];
  if (direct) {
    return direct.toLowerCase();
  }
  const apiView = snippet.match(/@api_view\s*\(\s*\[\s*["'](GET|POST|PUT|PATCH|DELETE)/i)?.[1];
  if (apiView) {
    return apiView.toLowerCase();
  }
  const methods = snippet.match(/@require_http_methods\s*\(\s*\[([^\]]+)]/i)?.[1]?.match(/["'](GET|POST|PUT|PATCH|DELETE)/i)?.[1];
  return methods?.toLowerCase() ?? "request";
}

interface SpringControllerPrefix {
  index: number;
  path: string;
}

function findJavaEndpoints(text: string): EndpointCandidate[] {
  const endpoints: EndpointCandidate[] = [];
  const prefixes = findSpringControllerPrefixes(text);
  const routeRegex =
    /@(?:(Get|Post|Put|Patch|Delete)Mapping|RequestMapping)\s*(?:\(([^)]*)\))?\s*(?:@[A-Za-z_$][A-Za-z0-9_$.]*(?:\s*\([^)]*\))?\s*)*(?:public|protected|private)\s+(?:static\s+)?[A-Za-z_$][A-Za-z0-9_$<>, ?\[\].]*\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)\s*(?:throws[^\{]+)?\{([\s\S]{0,2200}?)\}/g;

  for (const match of text.matchAll(routeRegex)) {
    const index = match.index ?? 0;
    const annotation = match[0].match(/@(\w+Mapping)\b/)?.[1] ?? "RequestMapping";
    const method = springRouteMethod(annotation, match[2] ?? "");
    const prefix = springControllerPrefixAt(prefixes, index);
    const path = joinSpringPaths(prefix, springRoutePath(match[2] ?? ""));
    const snippet = match[0];
    endpoints.push({
      kind: "java",
      method,
      path,
      index,
      endIndex: index + snippet.length,
      snippet
    });
  }

  return endpoints;
}

function findSpringControllerPrefixes(text: string): SpringControllerPrefix[] {
  const prefixes: SpringControllerPrefix[] = [];
  const controllerRegex =
    /@RequestMapping\s*\(([^)]*)\)\s*(?:@[A-Za-z_$][A-Za-z0-9_$.]*(?:\s*\([^)]*\))?\s*)*(?:public\s+)?(?:class|interface)\s+[A-Za-z_$][A-Za-z0-9_$]*/g;
  for (const match of text.matchAll(controllerRegex)) {
    prefixes.push({
      index: match.index ?? 0,
      path: springRoutePath(match[1] ?? "")
    });
  }
  return prefixes;
}

function springControllerPrefixAt(prefixes: readonly SpringControllerPrefix[], endpointIndex: number): string {
  let prefix = "";
  for (const candidate of prefixes) {
    if (candidate.index >= endpointIndex) {
      break;
    }
    prefix = candidate.path;
  }
  return prefix;
}

function springRouteMethod(annotation: string, argumentsText: string): string {
  const direct = annotation.match(/^(Get|Post|Put|Patch|Delete)Mapping$/i)?.[1];
  if (direct) {
    return direct.toLowerCase();
  }
  return argumentsText.match(/RequestMethod\s*\.\s*(GET|POST|PUT|PATCH|DELETE)/i)?.[1]?.toLowerCase() ?? "request";
}

function springRoutePath(argumentsText: string): string {
  const named = argumentsText.match(/\b(?:value|path)\s*=\s*["']([^"']+)["']/i)?.[1];
  const direct = argumentsText.match(/["']([^"']+)["']/)?.[1];
  return named ?? direct ?? "/";
}

function joinSpringPaths(prefix: string, path: string): string {
  if (!prefix || prefix === "/") {
    return path || "/";
  }
  if (!path || path === "/") {
    return prefix.startsWith("/") ? prefix : `/${prefix}`;
  }
  return `/${prefix}/${path}`.replace(/\/+/g, "/");
}

interface JavaScriptMiddlewareControls {
  authenticationPrefixes: string[];
  rateLimitPrefixes: string[];
}

function detectJavaScriptMiddlewareControls(text: string): JavaScriptMiddlewareControls {
  const controls: JavaScriptMiddlewareControls = {
    authenticationPrefixes: [],
    rateLimitPrefixes: []
  };
  const middlewareRegex = /\b(?:app|router)\s*\.\s*use\s*\(\s*(?:(["'`])([^"'`]+)\1\s*,\s*)?([^\r\n;]+)/g;

  for (const match of text.matchAll(middlewareRegex)) {
    const prefix = normalizeMiddlewarePrefix(match[2]);
    const middleware = match[3] ?? "";
    if (looksLikeAuthenticationMiddleware(middleware)) {
      controls.authenticationPrefixes.push(prefix);
    }
    if (looksLikeRateLimitMiddleware(middleware)) {
      controls.rateLimitPrefixes.push(prefix);
    }
  }

  controls.authenticationPrefixes = [...new Set(controls.authenticationPrefixes)];
  controls.rateLimitPrefixes = [...new Set(controls.rateLimitPrefixes)];
  return controls;
}

function normalizeMiddlewarePrefix(value: string | undefined): string {
  if (!value) {
    return "";
  }
  const normalized = value.trim().replace(/\/+$/, "");
  return normalized ? (normalized.startsWith("/") ? normalized : `/${normalized}`) : "";
}

function looksLikeAuthenticationMiddleware(value: string): boolean {
  return /(?:\b(?:authenticate|authorize)[A-Za-z_$]*\b|\brequire(?:auth|authentication|authorization|login)\b|\bverify(?:token|jwt)\b|\bprotect(?:ed)?\b|\bauth(?:entication|orization)?middleware\b|passport\s*\.\s*authenticate|expressjwt|\bjwtmiddleware\b)/i.test(
    value
  );
}

function looksLikeRateLimitMiddleware(value: string): boolean {
  return /(?:rate\s*limit|rateLimit(?:er)?|throttle|limiter)/i.test(value);
}

function describeMiddlewareControls(controls: JavaScriptMiddlewareControls): string[] {
  const descriptions: string[] = [];
  if (controls.authenticationPrefixes.length > 0) {
    descriptions.push(`Authentication middleware: ${formatMiddlewareScopes(controls.authenticationPrefixes)}`);
  }
  if (controls.rateLimitPrefixes.length > 0) {
    descriptions.push(`Rate-limit middleware: ${formatMiddlewareScopes(controls.rateLimitPrefixes)}`);
  }
  return descriptions;
}

function formatMiddlewareScopes(prefixes: readonly string[]): string {
  return prefixes.map((prefix) => prefix || "all routes").join(", ");
}

function middlewareAppliesToRoute(path: string, prefixes: readonly string[]): boolean {
  const route = path.startsWith("/") ? path : `/${path}`;
  return prefixes.some((prefix) => !prefix || route === prefix || route.startsWith(`${prefix}/`));
}

function evaluateEndpoint(endpoint: EndpointCandidate, middlewareControls: JavaScriptMiddlewareControls): SemanticRuleResult[] {
  const lower = endpoint.snippet.toLowerCase();
  const results: SemanticRuleResult[] = [];

  if (
    isSensitiveEndpoint(endpoint) &&
    !hasAuthentication(lower) &&
    !middlewareAppliesToRoute(endpoint.path, middlewareControls.authenticationPrefixes)
  ) {
    results.push({
      ruleId: "l3_missing_authentication",
      severity: "high",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} appears to access sensitive functionality without obvious authentication.`,
      suggestion: "Add authentication/authorization middleware or decorators before exposing this endpoint."
    });
  }

  if (
    needsRateLimit(endpoint) &&
    !hasRateLimit(lower) &&
    !middlewareAppliesToRoute(endpoint.path, middlewareControls.rateLimitPrefixes)
  ) {
    results.push({
      ruleId: "l3_missing_rate_limiting",
      severity: "medium",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} looks abuse-prone and has no obvious rate limiting.`,
      suggestion: "Add a rate limiter for login, registration, password reset, upload, or write-heavy endpoints."
    });
  }

  if (usesUserInput(endpoint) && !hasInputValidation(lower)) {
    results.push({
      ruleId: "l3_missing_input_validation",
      severity: "medium",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} uses request input without obvious validation.`,
      suggestion: "Validate and sanitize request body, query, and route parameters with an explicit schema or validator."
    });
  }

  if (usesUserInput(endpoint) && usesDatabase(lower) && hasDynamicSql(lower) && !hasParameterizedQuery(lower)) {
    results.push({
      ruleId: "l3_missing_parameterized_queries",
      severity: "high",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} appears to build a database query from request input without bound parameters.`,
      suggestion: "Use a prepared statement or query parameters instead of interpolating request values into SQL."
    });
  }

  if (performsIo(lower) && !hasErrorHandling(lower)) {
    results.push({
      ruleId: "l3_missing_error_handling",
      severity: "low",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} performs IO without obvious error handling.`,
      suggestion: "Handle failures with try/catch, promise rejection handling, or framework-specific error middleware and return a safe error response."
    });
  }

  if (returnsHtml(endpoint) && !hasOutputEncoding(lower)) {
    results.push({
      ruleId: "l3_missing_output_encoding",
      severity: "medium",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} returns HTML without obvious output encoding.`,
      suggestion: "Escape or sanitize dynamic values before returning HTML."
    });
  }

  return results;
}

function isSensitiveEndpoint(endpoint: EndpointCandidate): boolean {
  return /admin|account|billing|payment|profile|settings|user|token|secret|private/i.test(endpoint.path);
}

function needsRateLimit(endpoint: EndpointCandidate): boolean {
  return endpoint.method !== "get" || /login|register|signup|password|reset|token|upload|invite/i.test(endpoint.path);
}

function usesUserInput(endpoint: EndpointCandidate): boolean {
  return /\b(req\.(?:body|query|params)|request\.(?:json|form|args|GET|POST|body|FILES|headers|META)|body|query|params)\b|@(?:RequestBody|RequestParam|PathVariable|RequestHeader|ModelAttribute)\b|\bHttpServletRequest\b/i.test(
    endpoint.snippet
  );
}

function usesDatabase(lowerSnippet: string): boolean {
  return /\b(?:db|database|pool|client|connection|conn|session|cursor|repository)\s*\.\s*(?:query|execute|raw|find|create|update|delete|insert|save|persist)\b|\b[a-z_][a-z0-9_]*\.objects\s*\.\s*(?:get|filter|exclude|create|update|delete|bulk_create|bulk_update)\b|\b(?:select|insert|update|delete)\b/.test(
    lowerSnippet
  );
}

function hasDynamicSql(lowerSnippet: string): boolean {
  return /\b(?:select|insert|update|delete)\b[\s\S]{0,300}(?:\$\{|\+|\{[a-z_$]|%\s*(?:\(|[a-z_$]))/.test(lowerSnippet);
}

function hasParameterizedQuery(lowerSnippet: string): boolean {
  return (
    /\b(?:query|execute)\s*\(\s*[^,\n]+,\s*(?:\[[^\]]*\]|\([^)]*\)|\{[^}]*\}|params?\b|values?\b)/.test(lowerSnippet) ||
    /@query\s*\(\s*["'][^"']*(?:\?|:[a-z_$][a-z0-9_$]*)/i.test(lowerSnippet) ||
    /\b(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*(?:query|update|execute)\s*\(\s*[^,\n]+,\s*[^)]/.test(lowerSnippet)
  );
}

function performsIo(lowerSnippet: string): boolean {
  return (
    usesDatabase(lowerSnippet) ||
    /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|requests\.(?:get|post|put|patch|delete)|http\.get|fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream)|open|send_file|(?:child_process\.)?exec|subprocess\.(?:call|run|popen)|restTemplate\.(?:get|post|put|exchange)|webClient\.|files\.(?:read|write))\s*\(/.test(
      lowerSnippet
    )
  );
}

function returnsHtml(endpoint: EndpointCandidate): boolean {
  return /\b(?:res\.send|return)\s*\(?\s*[`"'][\s\S]{0,120}<[a-z][\s\S]*>/i.test(endpoint.snippet);
}

function hasAuthentication(lowerSnippet: string): boolean {
  return /\b(authenticate|authorize|requireauth|isauthenticated|verifytoken|jwt|session|current_user|depends\s*\(\s*get_current_user|login_required|permission_required|bearer|preauthorize|secured|rolesallowed|authentication|securitycontext|principal)\b/.test(
    lowerSnippet
  );
}

function hasRateLimit(lowerSnippet: string): boolean {
  return /\b(ratelimit|rate_limit|limiter|throttle|slowapi|express-rate-limit|bucket4j|@limit)\b/.test(lowerSnippet);
}

function hasInputValidation(lowerSnippet: string): boolean {
  return /\b(validate|validated|validator|schema|zod|joi|yup|pydantic|sanitize|escape|safeparse|parse_obj|basemodel|is_valid|full_clean|cleaned_data)\b|\bforms?\.(?:form|modelform)\b|@(?:valid|validated|notnull|notblank|notempty|size|pattern)\b/.test(
    lowerSnippet
  );
}

function hasErrorHandling(lowerSnippet: string): boolean {
  return /\btry\s*(?:\{|:)|\bcatch\s*\(|\.catch\s*\(|\bexcept\b|\bonerror\b|\b(?:handle|error)_?handler\b/.test(lowerSnippet);
}

function hasOutputEncoding(lowerSnippet: string): boolean {
  return /\b(escape|sanitize|dompurify|html\.escape|markupsafe|bleach|encode)\b/.test(lowerSnippet);
}

function inferPythonRouteMethod(decorator: string): string {
  const methodMatch = decorator.match(/methods\s*=\s*\[[^\]]*["']([A-Z]+)["']/);
  return methodMatch?.[1]?.toLowerCase() ?? "get";
}

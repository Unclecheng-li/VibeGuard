import type { Finding, L3AnalyzerLike, Severity, SourceFile } from "../types";
import { createFinding } from "../utils";

interface EndpointCandidate {
  kind: "javascript" | "python";
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

export class LocalSemanticAnalyzer implements L3AnalyzerLike {
  analyze(source: SourceFile, timestamp: number): Finding[] {
    return analyzeSecurityDimensions(source, timestamp);
  }
}

export function analyzeSecurityDimensions(source: SourceFile, timestamp: number): Finding[] {
  const candidates = [
    ...findJavaScriptEndpoints(source.text),
    ...findPythonEndpoints(source.text)
  ];
  const findings: Finding[] = [];

  for (const candidate of candidates) {
    const rules = evaluateEndpoint(candidate);
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
  return [
    "Analyze this function and check if it's missing critical security measures.",
    "",
    "Function code:",
    code,
    "",
    "Function context:",
    `- File: ${source.filePath}`,
    `- Language: ${source.languageId ?? "unknown"}`,
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

function evaluateEndpoint(endpoint: EndpointCandidate): SemanticRuleResult[] {
  const lower = endpoint.snippet.toLowerCase();
  const results: SemanticRuleResult[] = [];

  if (isSensitiveEndpoint(endpoint) && !hasAuthentication(lower)) {
    results.push({
      ruleId: "l3_missing_authentication",
      severity: "high",
      message: `Endpoint ${endpoint.method.toUpperCase()} ${endpoint.path} appears to access sensitive functionality without obvious authentication.`,
      suggestion: "Add authentication/authorization middleware or decorators before exposing this endpoint."
    });
  }

  if (needsRateLimit(endpoint) && !hasRateLimit(lower)) {
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
  return /\b(req\.(?:body|query|params)|request\.(?:json|form|args)|body|query|params)\b/i.test(endpoint.snippet);
}

function returnsHtml(endpoint: EndpointCandidate): boolean {
  return /\b(?:res\.send|return)\s*\(?\s*[`"'][\s\S]{0,120}<[a-z][\s\S]*>/i.test(endpoint.snippet);
}

function hasAuthentication(lowerSnippet: string): boolean {
  return /\b(authenticate|authorize|requireauth|isauthenticated|verifytoken|jwt|session|current_user|depends\s*\(\s*get_current_user|login_required|permission_required|bearer)\b/.test(lowerSnippet);
}

function hasRateLimit(lowerSnippet: string): boolean {
  return /\b(ratelimit|rate_limit|limiter|throttle|slowapi|express-rate-limit|@limit)\b/.test(lowerSnippet);
}

function hasInputValidation(lowerSnippet: string): boolean {
  return /\b(validate|validated|validator|schema|zod|joi|yup|pydantic|sanitize|escape|safeparse|parse_obj|basemodel)\b/.test(lowerSnippet);
}

function hasOutputEncoding(lowerSnippet: string): boolean {
  return /\b(escape|sanitize|dompurify|html\.escape|markupsafe|bleach|encode)\b/.test(lowerSnippet);
}

function inferPythonRouteMethod(decorator: string): string {
  const methodMatch = decorator.match(/methods\s*=\s*\[[^\]]*["']([A-Z]+)["']/);
  return methodMatch?.[1]?.toLowerCase() ?? "get";
}

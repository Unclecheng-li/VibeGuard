import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  OidcAuthenticationError,
  OidcDashboardAuthenticator,
  roleAllows,
  type DashboardIdentity,
  type DashboardRole,
  type OidcDashboardAuthOptions
} from "./auth";
import { createComplianceReport, type ComplianceFramework } from "./compliance";
import { formatFindingsDashboard } from "./dashboard";
import { FindingsIngestError, parseFindingsIngestPayload } from "./ingest";
import { SqliteFindingStore } from "./storage";

export interface FindingsDashboardServerOptions {
  dbPath: string;
  host?: string;
  port?: number;
  /** Break-glass service token. Keep it in an environment variable, never in a command line or source file. */
  token?: string;
  days?: number;
  topLimit?: number;
  /** Optionally pin all dashboard and API reads to one project identifier. */
  project?: string;
  title?: string;
  /** Standard OIDC sign-in and dashboard role mapping for enterprise deployments. */
  oidc?: OidcDashboardAuthOptions;
  /** Separate bearer token for CI to upload scan summaries. This does not grant dashboard access. */
  ingestToken?: string;
  /** Maximum findings accepted in one CI upload. Defaults to 10,000. */
  ingestMaxFindings?: number;
}

export interface StartedFindingsDashboardServer {
  url: string;
  server: Server;
  close(): Promise<void>;
}

/** Starts a private-deployment-friendly dashboard over the local findings database. */
export async function startFindingsDashboardServer(
  options: FindingsDashboardServerOptions
): Promise<StartedFindingsDashboardServer> {
  const host = options.host?.trim() || "127.0.0.1";
  const port = options.port ?? 8787;
  const token = options.token?.trim() || undefined;
  const ingestToken = options.ingestToken?.trim() || undefined;
  const ingestMaxFindings = validateIngestMaxFindings(options.ingestMaxFindings);
  const project = normalizeProject(options.project);
  const since = options.days === undefined ? undefined : Date.now() - options.days * 24 * 60 * 60 * 1000;
  const store = new SqliteFindingStore(options.dbPath);
  const authenticator = options.oidc ? new OidcDashboardAuthenticator(options.oidc) : undefined;
  let requestOptions: RequestOptions | undefined;
  const server = createServer((request, response) => {
    if (!requestOptions) {
      writeText(response, 503, "Service Unavailable\n", "text/plain; charset=utf-8");
      return;
    }
    void handleRequest(request, response, store, requestOptions).catch((error: unknown) => {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      const status = error instanceof OidcAuthenticationError ? error.status : 500;
      writeText(response, status, status >= 500 ? "Authentication service unavailable\n" : "Authentication failed\n", "text/plain; charset=utf-8");
    });
  });
  server.on("close", () => store.close());

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });

  const address = server.address();
  const actualPort = typeof address === "object" && address ? address.port : port;
  const url = `http://${host.includes(":") ? `[${host}]` : host}:${actualPort}/`;
  requestOptions = {
    ...options,
    token,
    ingestToken,
    ingestMaxFindings,
    project,
    since,
    authenticator,
    publicUrl: normalizePublicUrl(options.oidc?.publicUrl ?? url)
  };
  return {
    url,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      })
  };
}

interface RequestOptions extends FindingsDashboardServerOptions {
  since?: number;
  publicUrl: string;
  authenticator?: OidcDashboardAuthenticator;
  ingestToken?: string;
  ingestMaxFindings: number;
  project?: string;
}

interface RequestAuthentication {
  identity?: DashboardIdentity;
  cookieHeaders?: string[];
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  store: SqliteFindingStore,
  options: RequestOptions
): Promise<void> {
  const url = new URL(request.url ?? "/", options.publicUrl);
  if (url.pathname === "/healthz") {
    writeText(response, 200, "ok\n", "text/plain; charset=utf-8");
    return;
  }
  if (url.pathname === "/api/ingest") {
    if (request.method !== "POST") {
      writeText(response, 405, "Method Not Allowed\n", "text/plain; charset=utf-8", { Allow: "POST" });
      return;
    }
    await handleIngest(request, response, store, options);
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    writeText(response, 405, "Method Not Allowed\n", "text/plain; charset=utf-8", { Allow: "GET, HEAD" });
    return;
  }
  if (url.pathname === "/auth/login") {
    await handleLogin(url, response, options);
    return;
  }
  if (url.pathname === "/auth/callback") {
    await handleCallback(request, url, response, store, options);
    return;
  }
  if (url.pathname === "/auth/logout") {
    handleLogout(request, response, store, options);
    return;
  }

  const requiredRole: DashboardRole = url.pathname === "/api/audit"
    ? "admin"
    : url.pathname === "/api/findings" || url.pathname === "/api/compliance"
      ? "analyst"
      : "viewer";
  const authentication = authenticateRequest(request, url, options);
  if (!authentication.identity) {
    if (options.authenticator && (url.pathname === "/" || url.pathname === "/index.html")) {
      writeRedirect(response, `/auth/login?returnTo=${encodeURIComponent(`${url.pathname}${url.search}`)}`);
      return;
    }
    writeText(response, 401, "Unauthorized\n", "text/plain; charset=utf-8", {
      "WWW-Authenticate": 'Bearer realm="VibeGuard Team Dashboard"'
    });
    return;
  }
  if (!roleAllows(authentication.identity.role, requiredRole)) {
    recordDashboardAudit(store, authentication.identity, "dashboard.access_denied", "denied", {
      path: url.pathname,
      required_role: requiredRole
    });
    writeText(response, 403, "Forbidden\n", "text/plain; charset=utf-8", withCookies(undefined, authentication.cookieHeaders));
    return;
  }
  const project = requestProjectFilter(url, options);
  if (project === "invalid") {
    writeText(response, 400, "Invalid project filter\n", "text/plain; charset=utf-8", withCookies(undefined, authentication.cookieHeaders));
    return;
  }

  if (url.pathname === "/api/session") {
    writeJson(response, 200, publicIdentity(authentication.identity), withCookies(undefined, authentication.cookieHeaders));
    return;
  }
  if (url.pathname === "/api/summary") {
    const summary = store.summary({ since: options.since, topLimit: options.topLimit, project });
    writeJson(response, 200, summary, withCookies(undefined, authentication.cookieHeaders));
    return;
  }
  if (url.pathname === "/api/findings") {
    const limit = parseLimit(url.searchParams.get("limit"));
    const includeDismissed = url.searchParams.get("all") === "true" && authentication.identity.role === "admin";
    recordDashboardAudit(store, authentication.identity, "dashboard.findings_viewed", "success", {
      limit,
      include_dismissed: includeDismissed,
      ...(project ? { project } : {})
    });
    writeJson(response, 200, store.listFindings({ limit, includeDismissed, project }), withCookies(undefined, authentication.cookieHeaders));
    return;
  }
  if (url.pathname === "/api/compliance") {
    const frameworks = parseComplianceFrameworks(url.searchParams.getAll("framework"));
    if (frameworks === "invalid") {
      writeText(response, 400, "Invalid compliance framework\n", "text/plain; charset=utf-8", withCookies(undefined, authentication.cookieHeaders));
      return;
    }
    const summary = store.summary({ since: options.since, topLimit: options.topLimit, project });
    recordDashboardAudit(store, authentication.identity, "dashboard.compliance_viewed", "success", {
      framework_count: frameworks?.length ?? 2,
      ...(project ? { project } : {})
    });
    writeJson(
      response,
      200,
      createComplianceReport(summary, {
        frameworks,
        auditEvents: project ? [] : store.listAuditEvents({ since: options.since, limit: 1000 })
      }),
      withCookies(undefined, authentication.cookieHeaders)
    );
    return;
  }
  if (url.pathname === "/api/audit") {
    const limit = parseLimit(url.searchParams.get("limit"));
    const events = store.listAuditEvents({ limit });
    recordDashboardAudit(store, authentication.identity, "dashboard.audit_log_viewed", "success", { limit });
    writeJson(response, 200, events, withCookies(undefined, authentication.cookieHeaders));
    return;
  }
  if (url.pathname === "/" || url.pathname === "/index.html") {
    const summary = store.summary({ since: options.since, topLimit: options.topLimit, project });
    const html = formatFindingsDashboard(summary, {
      dbPath: options.dbPath,
      generatedAt: Date.now(),
      title: options.title ?? "VibeGuard Team Security Dashboard"
    });
    writeText(response, 200, html, "text/html; charset=utf-8", withCookies(undefined, authentication.cookieHeaders));
    return;
  }
  writeText(response, 404, "Not Found\n", "text/plain; charset=utf-8", withCookies(undefined, authentication.cookieHeaders));
}

async function handleIngest(
  request: IncomingMessage,
  response: ServerResponse,
  store: SqliteFindingStore,
  options: RequestOptions
): Promise<void> {
  if (!options.ingestToken) {
    writeText(response, 404, "Not Found\n", "text/plain; charset=utf-8");
    return;
  }
  const bearer = request.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!bearer || !tokensMatch(options.ingestToken, bearer)) {
    writeText(response, 401, "Unauthorized\n", "text/plain; charset=utf-8", {
      "WWW-Authenticate": 'Bearer realm="VibeGuard Findings Ingest"'
    });
    return;
  }
  const contentType = request.headers["content-type"];
  if (typeof contentType !== "string" || !/^application\/json(?:;|$)/i.test(contentType.trim())) {
    writeText(response, 415, "Expected application/json\n", "text/plain; charset=utf-8");
    return;
  }
  try {
    const payload = parseFindingsIngestPayload(await readJsonBody(request), {
      maxFindings: options.ingestMaxFindings
    });
    const run = store.recordScanRun(payload);
    try {
      store.recordAuditEvent({
        authentication: "ingest",
        action: "findings.ingested",
        outcome: "success",
        details: {
          finding_count: run.findingCount,
          file_count: run.fileCount
        }
      });
    } catch {
      // The scan result remains durable even if its audit record cannot be written.
    }
    writeJson(response, 201, {
      scanId: run.scanId,
      findingCount: run.findingCount,
      activeCount: run.activeCount,
      dismissedCount: run.dismissedCount
    });
  } catch (error) {
    if (error instanceof FindingsIngestError) {
      writeText(response, error.status, `${error.message}\n`, "text/plain; charset=utf-8");
      return;
    }
    writeText(response, 400, "Invalid findings ingest payload\n", "text/plain; charset=utf-8");
  }
}

async function handleLogin(url: URL, response: ServerResponse, options: RequestOptions): Promise<void> {
  if (!options.authenticator) {
    writeText(response, 404, "Not Found\n", "text/plain; charset=utf-8");
    return;
  }
  const result = await options.authenticator.beginLogin(callbackUrl(options), url.searchParams.get("returnTo"));
  writeRedirect(response, result.location, { "Set-Cookie": result.stateCookie });
}

async function handleCallback(
  request: IncomingMessage,
  url: URL,
  response: ServerResponse,
  store: SqliteFindingStore,
  options: RequestOptions
): Promise<void> {
  if (!options.authenticator) {
    writeText(response, 404, "Not Found\n", "text/plain; charset=utf-8");
    return;
  }
  const result = await options.authenticator.finishLogin(callbackUrl(options), url.searchParams, request.headers.cookie);
  recordDashboardAudit(store, result.identity, "dashboard.sign_in", "success");
  writeRedirect(response, result.location, { "Set-Cookie": [result.sessionCookie, result.clearStateCookie] });
}

function handleLogout(request: IncomingMessage, response: ServerResponse, store: SqliteFindingStore, options: RequestOptions): void {
  if (!options.authenticator) {
    writeText(response, 404, "Not Found\n", "text/plain; charset=utf-8");
    return;
  }
  const identity = options.authenticator.readSession(request.headers.cookie);
  if (identity) {
    recordDashboardAudit(store, identity, "dashboard.sign_out", "success");
  }
  writeRedirect(response, "/", { "Set-Cookie": options.authenticator.clearSessionCookie(callbackUrl(options)) });
}

function authenticateRequest(request: IncomingMessage, url: URL, options: RequestOptions): RequestAuthentication {
  const token = options.token;
  const authorization = request.headers.authorization;
  const bearer = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  const cookieToken = readCookie(request.headers.cookie, "vibeguard_team_token");
  const queryToken = url.searchParams.get("token") ?? undefined;
  const provided = bearer ?? cookieToken ?? queryToken;
  if (token && provided && tokensMatch(token, provided)) {
    return {
      identity: { subject: "service-token", role: "admin", authentication: "token" },
      cookieHeaders: queryToken && tokensMatch(token, queryToken)
        ? [`vibeguard_team_token=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/`]
        : undefined
    };
  }
  const oidcIdentity = options.authenticator?.readSession(request.headers.cookie);
  if (oidcIdentity) {
    return { identity: oidcIdentity };
  }
  if (!token && !options.authenticator) {
    return { identity: { subject: "anonymous", role: "admin", authentication: "anonymous" } };
  }
  return {};
}

function callbackUrl(options: RequestOptions): string {
  return new URL("/auth/callback", options.publicUrl).toString();
}

function normalizePublicUrl(value: string): string {
  const url = new URL(value);
  return url.toString().replace(/\/$/, "");
}

function normalizeProject(value: string | undefined): string | undefined {
  const project = value?.trim();
  if (!project) {
    return undefined;
  }
  if (project.length > 256) {
    throw new Error("Dashboard project must be at most 256 characters.");
  }
  return project;
}

function requestProjectFilter(url: URL, options: RequestOptions): string | undefined | "invalid" {
  if (options.project) {
    return options.project;
  }
  try {
    return normalizeProject(url.searchParams.get("project") ?? undefined);
  } catch {
    return "invalid";
  }
}

function publicIdentity(identity: DashboardIdentity): Pick<DashboardIdentity, "subject" | "role" | "name" | "email" | "authentication"> {
  return identity;
}

function parseLimit(value: string | null): number {
  if (!value) {
    return 50;
  }
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, 1000) : 50;
}

function parseComplianceFrameworks(values: string[]): ComplianceFramework[] | undefined | "invalid" {
  if (values.length === 0) {
    return undefined;
  }
  const result: ComplianceFramework[] = [];
  for (const value of values.flatMap((item) => item.split(","))) {
    if (value === "all") {
      return ["soc2", "iso27001"];
    }
    if (value !== "soc2" && value !== "iso27001") {
      return "invalid";
    }
    if (!result.includes(value)) {
      result.push(value);
    }
  }
  return result.length > 0 ? result : undefined;
}

function recordDashboardAudit(
  store: SqliteFindingStore,
  identity: DashboardIdentity,
  action: string,
  outcome: "success" | "denied",
  details?: Record<string, string | number | boolean>
): void {
  try {
    store.recordAuditEvent({
      subject: identity.subject,
      role: identity.role,
      authentication: identity.authentication,
      action,
      outcome,
      details
    });
  } catch {
    // Dashboard reads remain available if an audit write cannot be persisted.
  }
}

function readCookie(header: string | undefined, name: string): string | undefined {
  const value = header?.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`))?.[1];
  if (!value) {
    return undefined;
  }
  try {
    return decodeURIComponent(value);
  } catch {
    return undefined;
  }
}

function tokensMatch(expected: string, provided: string): boolean {
  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(provided);
  return expectedBuffer.length === providedBuffer.length && timingSafeEqual(expectedBuffer, providedBuffer);
}

async function readJsonBody(request: IncomingMessage, maxBytes = 5 * 1024 * 1024): Promise<unknown> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > maxBytes) {
      throw new FindingsIngestError("Findings ingest payload exceeds the 5 MiB limit.", 413);
    }
    chunks.push(buffer);
  }
  if (bytes === 0) {
    throw new FindingsIngestError("Findings ingest payload must not be empty.");
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new FindingsIngestError("Findings ingest payload must be valid JSON.");
  }
}

function validateIngestMaxFindings(value: number | undefined): number {
  if (value === undefined) {
    return 10_000;
  }
  if (!Number.isInteger(value) || value < 1 || value > 10_000) {
    throw new Error("ingestMaxFindings must be an integer between 1 and 10000.");
  }
  return value;
}

function withCookies(headers: ResponseHeaders | undefined, cookies: string[] | undefined): ResponseHeaders | undefined {
  if (!cookies?.length) {
    return headers;
  }
  return { ...headers, "Set-Cookie": cookies };
}

type ResponseHeaders = Record<string, string | string[]>;

function writeJson(response: ServerResponse, status: number, value: unknown, headers?: ResponseHeaders): void {
  writeText(response, status, JSON.stringify(value), "application/json; charset=utf-8", headers);
}

function writeRedirect(response: ServerResponse, location: string, headers?: ResponseHeaders): void {
  response.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
    ...headers
  });
  response.end();
}

function writeText(
  response: ServerResponse,
  status: number,
  body: string,
  contentType: string,
  headers?: ResponseHeaders
): void {
  response.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...headers
  });
  response.end(body);
}

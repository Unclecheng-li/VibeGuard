import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { formatFindingsDashboard } from "./dashboard";
import { SqliteFindingStore, type FindingStoreSummary } from "./storage";

export interface FindingsDashboardServerOptions {
  dbPath: string;
  host?: string;
  port?: number;
  token?: string;
  days?: number;
  topLimit?: number;
  title?: string;
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
  const since = options.days === undefined ? undefined : Date.now() - options.days * 24 * 60 * 60 * 1000;
  const store = new SqliteFindingStore(options.dbPath);
  const server = createServer((request, response) => {
    handleRequest(request, response, store, { ...options, token, since });
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
  return {
    url: `http://${host.includes(":") ? `[${host}]` : host}:${actualPort}/`,
    server,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      })
  };
}

interface RequestOptions extends FindingsDashboardServerOptions {
  since?: number;
}

function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  store: SqliteFindingStore,
  options: RequestOptions
): void {
  const url = new URL(request.url ?? "/", "http://vibeguard.local");
  if (url.pathname === "/healthz") {
    writeText(response, 200, "ok\n", "text/plain; charset=utf-8");
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    writeText(response, 405, "Method Not Allowed\n", "text/plain; charset=utf-8", { Allow: "GET, HEAD" });
    return;
  }

  const authenticatedByQuery = isAuthorized(request, url, options.token);
  if (options.token && !authenticatedByQuery.authorized) {
    writeText(response, 401, "Unauthorized\n", "text/plain; charset=utf-8", {
      "WWW-Authenticate": 'Bearer realm="VibeGuard Team Dashboard"'
    });
    return;
  }

  const summary = store.summary({ since: options.since, topLimit: options.topLimit });
  const cookieHeaders = authenticatedByQuery.fromQuery && options.token
    ? { "Set-Cookie": `vibeguard_team_token=${encodeURIComponent(options.token)}; HttpOnly; SameSite=Strict; Path=/` }
    : undefined;
  if (url.pathname === "/api/summary") {
    writeJson(response, 200, summary, cookieHeaders);
    return;
  }
  if (url.pathname === "/" || url.pathname === "/index.html") {
    const html = formatFindingsDashboard(summary, {
      dbPath: options.dbPath,
      generatedAt: Date.now(),
      title: options.title ?? "VibeGuard Team Security Dashboard"
    });
    writeText(response, 200, html, "text/html; charset=utf-8", cookieHeaders);
    return;
  }
  writeText(response, 404, "Not Found\n", "text/plain; charset=utf-8", cookieHeaders);
}

function isAuthorized(
  request: IncomingMessage,
  url: URL,
  token: string | undefined
): { authorized: boolean; fromQuery: boolean } {
  if (!token) {
    return { authorized: true, fromQuery: false };
  }
  const authorization = request.headers.authorization;
  const bearer = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  const cookie = request.headers.cookie?.match(/(?:^|;\s*)vibeguard_team_token=([^;]+)/)?.[1];
  const query = url.searchParams.get("token") ?? undefined;
  const provided = bearer ?? (cookie ? decodeURIComponent(cookie) : undefined) ?? query;
  return {
    authorized: provided !== undefined && tokensMatch(token, provided),
    fromQuery: query !== undefined && tokensMatch(token, query)
  };
}

function tokensMatch(expected: string, provided: string): boolean {
  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(provided);
  return expectedBuffer.length === providedBuffer.length && timingSafeEqual(expectedBuffer, providedBuffer);
}

function writeJson(response: ServerResponse, status: number, value: FindingStoreSummary, headers?: Record<string, string>): void {
  writeText(response, status, JSON.stringify(value), "application/json; charset=utf-8", headers);
}

function writeText(
  response: ServerResponse,
  status: number,
  body: string,
  contentType: string,
  headers?: Record<string, string>
): void {
  response.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    ...headers
  });
  response.end(body);
}

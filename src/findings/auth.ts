import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
  type JsonWebKey
} from "node:crypto";

export type DashboardRole = "viewer" | "analyst" | "admin";
export type DashboardAccessRole = DashboardRole | "none";

export interface OidcDashboardAuthOptions {
  /** OIDC issuer URL. HTTPS is required except for localhost development. */
  issuer: string;
  clientId: string;
  clientSecret?: string;
  /** At least 32 random characters, kept outside source control. */
  sessionSecret: string;
  /** Public dashboard origin used to build the redirect URI behind a reverse proxy. */
  publicUrl?: string;
  roleClaim?: string;
  roleMappings?: Record<string, DashboardRole>;
  /** Users without a mapped group are denied unless explicitly assigned a default role. */
  defaultRole?: DashboardAccessRole;
  secureCookies?: boolean;
  fetcher?: typeof globalThis.fetch;
}

export interface DashboardIdentity {
  subject: string;
  role: DashboardAccessRole;
  name?: string;
  email?: string;
  authentication: "oidc" | "token" | "anonymous";
}

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface OidcState {
  state: string;
  verifier: string;
  nonce: string;
  returnTo: string;
  expiresAt: number;
}

interface DashboardSession {
  sub: string;
  role: DashboardAccessRole;
  exp: number;
  name?: string;
  email?: string;
}

interface IdTokenClaims {
  iss?: unknown;
  aud?: unknown;
  azp?: unknown;
  exp?: unknown;
  nonce?: unknown;
  sub?: unknown;
  name?: unknown;
  email?: unknown;
  [key: string]: unknown;
}

export interface OidcLoginResult {
  location: string;
  stateCookie: string;
}

export interface OidcCallbackResult {
  location: string;
  sessionCookie: string;
  clearStateCookie: string;
  identity: DashboardIdentity;
}

export class OidcAuthenticationError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "OidcAuthenticationError";
  }
}

/**
 * Small, dependency-free OIDC client for the private dashboard. It validates the
 * authorization-code response with PKCE and verifies the signed ID token against JWKS.
 */
export class OidcDashboardAuthenticator {
  private readonly issuer: string;
  private readonly fetcher: typeof globalThis.fetch;
  private discoveryPromise: Promise<OidcDiscovery> | undefined;

  constructor(private readonly options: OidcDashboardAuthOptions) {
    this.issuer = normalizeIssuer(options.issuer);
    if (!options.clientId.trim()) {
      throw new Error("OIDC client id must not be empty.");
    }
    if (Buffer.byteLength(options.sessionSecret, "utf8") < 32) {
      throw new Error("OIDC session secret must be at least 32 bytes.");
    }
    this.fetcher = options.fetcher ?? globalThis.fetch;
  }

  async beginLogin(callbackUrl: string, returnTo: string | null): Promise<OidcLoginResult> {
    const discovery = await this.discovery();
    const state: OidcState = {
      state: randomToken(),
      verifier: randomToken(),
      nonce: randomToken(),
      returnTo: normalizeReturnTo(returnTo),
      expiresAt: Date.now() + 10 * 60 * 1000
    };
    const authorizationUrl = new URL(discovery.authorization_endpoint);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("client_id", this.options.clientId);
    authorizationUrl.searchParams.set("redirect_uri", callbackUrl);
    authorizationUrl.searchParams.set("scope", "openid profile email");
    authorizationUrl.searchParams.set("state", state.state);
    authorizationUrl.searchParams.set("nonce", state.nonce);
    authorizationUrl.searchParams.set("code_challenge", base64Url(createHash("sha256").update(state.verifier).digest()));
    authorizationUrl.searchParams.set("code_challenge_method", "S256");

    return {
      location: authorizationUrl.toString(),
      stateCookie: serializeCookie("vibeguard_oidc_state", signValue(state, this.options.sessionSecret), {
        path: "/auth/callback",
        maxAgeSeconds: 10 * 60,
        secure: this.shouldUseSecureCookies(callbackUrl),
        sameSite: "Lax"
      })
    };
  }

  async finishLogin(callbackUrl: string, query: URLSearchParams, cookieHeader: string | undefined): Promise<OidcCallbackResult> {
    const state = readSignedValue<OidcState>(readCookie(cookieHeader, "vibeguard_oidc_state"), this.options.sessionSecret);
    if (!state || !isOidcState(state) || state.expiresAt < Date.now()) {
      throw new OidcAuthenticationError("The sign-in request has expired. Start again.", 400);
    }
    const queryState = query.get("state");
    if (!queryState || !stringsMatch(state.state, queryState)) {
      throw new OidcAuthenticationError("The sign-in state did not match.", 400);
    }
    if (query.get("error")) {
      throw new OidcAuthenticationError("The identity provider rejected the sign-in request.", 401);
    }
    const code = query.get("code");
    if (!code) {
      throw new OidcAuthenticationError("The identity provider did not return an authorization code.", 400);
    }

    const discovery = await this.discovery();
    const tokenResponse = await this.fetchJson(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: callbackUrl,
        client_id: this.options.clientId,
        ...(this.options.clientSecret ? { client_secret: this.options.clientSecret } : {}),
        code_verifier: state.verifier
      }).toString()
    });
    const idToken = typeof tokenResponse.id_token === "string" ? tokenResponse.id_token : undefined;
    if (!idToken) {
      throw new OidcAuthenticationError("The identity provider did not return an ID token.", 502);
    }
    const identity = await this.validateIdToken(idToken, state.nonce, discovery);
    const session: DashboardSession = {
      sub: identity.subject,
      role: identity.role,
      name: identity.name,
      email: identity.email,
      exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60
    };
    const secure = this.shouldUseSecureCookies(callbackUrl);
    return {
      location: state.returnTo,
      sessionCookie: serializeCookie("vibeguard_team_session", signValue(session, this.options.sessionSecret), {
        path: "/",
        maxAgeSeconds: 8 * 60 * 60,
        secure,
        sameSite: "Lax"
      }),
      clearStateCookie: clearCookie("vibeguard_oidc_state", "/auth/callback", secure),
      identity
    };
  }

  readSession(cookieHeader: string | undefined): DashboardIdentity | undefined {
    const session = readSignedValue<DashboardSession>(readCookie(cookieHeader, "vibeguard_team_session"), this.options.sessionSecret);
    if (!session || !isDashboardSession(session) || session.exp <= Math.floor(Date.now() / 1000)) {
      return undefined;
    }
    return {
      subject: session.sub,
      role: session.role,
      name: session.name,
      email: session.email,
      authentication: "oidc"
    };
  }

  clearSessionCookie(callbackUrl: string): string {
    return clearCookie("vibeguard_team_session", "/", this.shouldUseSecureCookies(callbackUrl));
  }

  private async discovery(): Promise<OidcDiscovery> {
    this.discoveryPromise ??= this.fetchDiscovery();
    return this.discoveryPromise;
  }

  private async fetchDiscovery(): Promise<OidcDiscovery> {
    const value = await this.fetchJson(`${this.issuer}/.well-known/openid-configuration`);
    const discovery: OidcDiscovery = {
      issuer: typeof value.issuer === "string" ? normalizeIssuer(value.issuer) : "",
      authorization_endpoint: typeof value.authorization_endpoint === "string" ? value.authorization_endpoint : "",
      token_endpoint: typeof value.token_endpoint === "string" ? value.token_endpoint : "",
      jwks_uri: typeof value.jwks_uri === "string" ? value.jwks_uri : ""
    };
    if (
      discovery.issuer !== this.issuer ||
      !isSafeProviderUrl(discovery.authorization_endpoint) ||
      !isSafeProviderUrl(discovery.token_endpoint) ||
      !isSafeProviderUrl(discovery.jwks_uri)
    ) {
      throw new OidcAuthenticationError("OIDC discovery returned an invalid provider configuration.", 502);
    }
    return discovery;
  }

  private async validateIdToken(token: string, expectedNonce: string, discovery: OidcDiscovery): Promise<DashboardIdentity> {
    if (token.length > 16_384) {
      throw new OidcAuthenticationError("The ID token is too large.", 401);
    }
    const segments = token.split(".");
    if (segments.length !== 3) {
      throw new OidcAuthenticationError("The identity provider returned an invalid ID token.", 401);
    }
    const header = parseJsonObject(decodeBase64Url(segments[0]));
    const claims = parseJsonObject(decodeBase64Url(segments[1])) as IdTokenClaims;
    const alg = typeof header.alg === "string" ? header.alg : "";
    const kid = typeof header.kid === "string" ? header.kid : "";
    if (!kid || !["RS256", "RS384", "RS512"].includes(alg)) {
      throw new OidcAuthenticationError("The ID token uses an unsupported signing algorithm.", 401);
    }
    const jwks = await this.fetchJson(discovery.jwks_uri);
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    const jwk = keys.find((candidate) => isMatchingJwk(candidate, kid, alg));
    if (!jwk) {
      throw new OidcAuthenticationError("The ID token signing key is unavailable.", 401);
    }
    let signatureValid = false;
    try {
      const publicKey = createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
      signatureValid = verify(
        { RS256: "RSA-SHA256", RS384: "RSA-SHA384", RS512: "RSA-SHA512" }[alg]!,
        Buffer.from(`${segments[0]}.${segments[1]}`),
        publicKey,
        Buffer.from(segments[2], "base64url")
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      throw new OidcAuthenticationError("The ID token signature is invalid.", 401);
    }
    if (
      claims.iss !== discovery.issuer ||
      !audienceIncludes(claims.aud, this.options.clientId) ||
      !isFutureExpiration(claims.exp) ||
      typeof claims.nonce !== "string" ||
      !stringsMatch(claims.nonce, expectedNonce) ||
      typeof claims.sub !== "string" ||
      !claims.sub
    ) {
      throw new OidcAuthenticationError("The ID token claims are invalid.", 401);
    }
    if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== this.options.clientId) {
      throw new OidcAuthenticationError("The ID token authorized party is invalid.", 401);
    }
    return {
      subject: claims.sub.slice(0, 256),
      role: roleForClaims(claims, this.options),
      name: stringClaim(claims.name),
      email: stringClaim(claims.email),
      authentication: "oidc"
    };
  }

  private async fetchJson(url: string, init?: RequestInit): Promise<Record<string, unknown>> {
    let response: Response;
    try {
      response = await this.fetcher(url, { ...init, redirect: "error" });
    } catch {
      throw new OidcAuthenticationError("The identity provider could not be reached.", 502);
    }
    if (!response.ok) {
      throw new OidcAuthenticationError("The identity provider rejected the request.", 502);
    }
    try {
      const value = await response.json();
      if (!isRecord(value)) {
        throw new Error("not an object");
      }
      return value;
    } catch {
      throw new OidcAuthenticationError("The identity provider returned an invalid response.", 502);
    }
  }

  private shouldUseSecureCookies(callbackUrl: string): boolean {
    if (this.options.secureCookies !== undefined) {
      return this.options.secureCookies;
    }
    return new URL(callbackUrl).protocol === "https:";
  }
}

export function roleAllows(role: DashboardAccessRole, required: DashboardRole): boolean {
  const levels: Record<DashboardAccessRole, number> = { none: 0, viewer: 1, analyst: 2, admin: 3 };
  return levels[role] >= levels[required];
}

function normalizeIssuer(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("OIDC issuer must be an absolute URL.");
  }
  if (!isSafeProviderUrl(url.toString())) {
    throw new Error("OIDC issuer must use HTTPS outside localhost development.");
  }
  return url.toString().replace(/\/$/, "");
}

function isSafeProviderUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1"));
  } catch {
    return false;
  }
}

function normalizeReturnTo(value: string | null): string {
  return value && value.startsWith("/") && !value.startsWith("//") ? value : "/";
}

function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function base64Url(value: Buffer): string {
  return value.toString("base64url");
}

function signValue(value: unknown, secret: string): string {
  const payload = Buffer.from(JSON.stringify(value)).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function readSignedValue<T>(value: string | undefined, secret: string): T | undefined {
  if (!value) {
    return undefined;
  }
  const separator = value.lastIndexOf(".");
  if (separator <= 0) {
    return undefined;
  }
  const payload = value.slice(0, separator);
  const signature = value.slice(separator + 1);
  const expected = createHmac("sha256", secret).update(payload).digest("base64url");
  if (!stringsMatch(signature, expected)) {
    return undefined;
  }
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as T;
  } catch {
    return undefined;
  }
}

function stringsMatch(expected: string, provided: string): boolean {
  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(provided);
  return expectedBuffer.length === providedBuffer.length && timingSafeEqual(expectedBuffer, providedBuffer);
}

function parseJsonObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value);
    if (!isRecord(parsed)) {
      throw new Error("not an object");
    }
    return parsed;
  } catch {
    throw new OidcAuthenticationError("The identity provider returned an invalid ID token.", 401);
  }
}

function decodeBase64Url(value: string): string {
  try {
    return Buffer.from(value, "base64url").toString("utf8");
  } catch {
    throw new OidcAuthenticationError("The identity provider returned an invalid ID token.", 401);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMatchingJwk(candidate: unknown, kid: string, alg: string): candidate is Record<string, unknown> {
  return (
    isRecord(candidate) &&
    candidate.kty === "RSA" &&
    candidate.kid === kid &&
    (candidate.use === undefined || candidate.use === "sig") &&
    (candidate.alg === undefined || candidate.alg === alg)
  );
}

function audienceIncludes(value: unknown, clientId: string): boolean {
  return value === clientId || (Array.isArray(value) && value.some((candidate) => candidate === clientId));
}

function isFutureExpiration(value: unknown): boolean {
  return typeof value === "number" && Number.isFinite(value) && value > Math.floor(Date.now() / 1000) - 30;
}

function roleForClaims(claims: IdTokenClaims, options: OidcDashboardAuthOptions): DashboardAccessRole {
  const claim = readClaim(claims, options.roleClaim ?? "roles");
  const candidates = typeof claim === "string" ? [claim] : Array.isArray(claim) ? claim.filter((value): value is string => typeof value === "string") : [];
  const mapped = candidates
    .map((value) => options.roleMappings?.[value])
    .filter((value): value is DashboardRole => value === "viewer" || value === "analyst" || value === "admin");
  if (mapped.includes("admin")) {
    return "admin";
  }
  if (mapped.includes("analyst")) {
    return "analyst";
  }
  if (mapped.includes("viewer")) {
    return "viewer";
  }
  return options.defaultRole ?? "none";
}

function readClaim(claims: IdTokenClaims, path: string): unknown {
  let current: unknown = claims;
  for (const segment of path.split(".")) {
    if (!isRecord(current) || !segment) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value.slice(0, 256) : undefined;
}

function isOidcState(value: OidcState): boolean {
  return (
    typeof value.state === "string" &&
    typeof value.verifier === "string" &&
    typeof value.nonce === "string" &&
    typeof value.returnTo === "string" &&
    typeof value.expiresAt === "number"
  );
}

function isDashboardSession(value: DashboardSession): boolean {
  return (
    typeof value.sub === "string" &&
    (value.role === "viewer" || value.role === "analyst" || value.role === "admin" || value.role === "none") &&
    typeof value.exp === "number"
  );
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

function serializeCookie(
  name: string,
  value: string,
  options: { path: string; maxAgeSeconds: number; secure: boolean; sameSite: "Lax" | "Strict" }
): string {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=${options.sameSite}; Path=${options.path}; Max-Age=${options.maxAgeSeconds}${options.secure ? "; Secure" : ""}`;
}

function clearCookie(name: string, path: string, secure: boolean): string {
  return `${name}=; HttpOnly; SameSite=Lax; Path=${path}; Max-Age=0${secure ? "; Secure" : ""}`;
}

export type SubscriptionPlan = "free" | "pro" | "team" | "enterprise";
export type SubscriptionState = "active" | "trialing" | "past_due" | "canceled" | "inactive";

export interface L3RequestUsage {
  used: number;
  limit: number;
  resetAt?: string;
}

export interface ProSubscriptionStatus {
  active: boolean;
  plan: SubscriptionPlan;
  state: SubscriptionState;
  features: string[];
  l3Requests?: L3RequestUsage;
  reason?: "missing_credential";
}

export interface ProSubscriptionStatusOptions {
  apiKey?: string;
  baseUrl?: string;
  fetchImpl?: typeof globalThis.fetch;
  timeoutMs?: number;
}

const defaultApiBaseUrl = "https://api.vibeguard.dev/v1";

/** Returns the hosted Pro API base URL, optionally overridden for a private deployment. */
export function defaultProApiBaseUrl(): string {
  return process.env.VIBEGUARD_PRO_API_BASE_URL?.trim() || defaultApiBaseUrl;
}

/** Reads the official Pro credential without ever placing it in config.json. */
export function getProApiKeyFromEnv(explicitEnvVar?: string): string | undefined {
  const names = explicitEnvVar ? [explicitEnvVar] : ["VIBEGUARD_PRO_API_KEY"];
  for (const name of names) {
    const value = process.env[name]?.trim();
    if (value) {
      return value;
    }
  }
  return undefined;
}

/**
 * Reads the hosted account's effective plan and remaining L3 request allowance.
 * The server remains the source of truth for billing and request enforcement.
 */
export async function getProSubscriptionStatus(options: ProSubscriptionStatusOptions = {}): Promise<ProSubscriptionStatus> {
  const apiKey = options.apiKey?.trim();
  if (!apiKey) {
    return {
      active: false,
      plan: "free",
      state: "inactive",
      features: [],
      reason: "missing_credential"
    };
  }
  const response = await fetchWithTimeout(
    proApiEndpoint(options.baseUrl ?? defaultProApiBaseUrl(), "/account/usage"),
    {
      method: "GET",
      headers: {
        authorization: `Bearer ${apiKey}`,
        accept: "application/json"
      }
    },
    options
  );
  const raw = await response.text();
  if (!response.ok) {
    throw new Error(`VibeGuard Pro subscription request failed: HTTP ${response.status}.`);
  }
  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    throw new Error("VibeGuard Pro subscription service returned invalid JSON.");
  }
  return parseProSubscriptionStatus(payload);
}

export function parseProSubscriptionStatus(value: unknown): ProSubscriptionStatus {
  const payload = isRecord(value) ? value : {};
  const plan = parsePlan(payload.plan);
  const state = parseState(payload.status ?? payload.state);
  const explicitActive = typeof payload.active === "boolean" ? payload.active : undefined;
  const active = explicitActive ?? (plan !== "free" && (state === "active" || state === "trialing"));
  const features = stringArray(payload.features);
  const usageContainer = isRecord(payload.usage) ? payload.usage : {};
  const l3Requests = parseL3Usage(usageContainer.l3_requests ?? usageContainer.l3Requests);
  return {
    active,
    plan,
    state,
    features,
    ...(l3Requests ? { l3Requests } : {})
  };
}

export function proApiEndpoint(baseUrl: string, endpoint: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new Error("VibeGuard Pro API URL must be an absolute URL.");
  }
  if (!isSecureApiUrl(url)) {
    throw new Error("VibeGuard Pro API URL must use HTTPS outside localhost development.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("VibeGuard Pro API URL must not include credentials, query parameters, or fragments.");
  }
  const normalizedEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  return `${url.toString().replace(/\/$/, "")}${normalizedEndpoint}`;
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  options: ProSubscriptionStatusOptions
): Promise<Response> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5000);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal, redirect: "error" });
  } catch {
    throw new Error("VibeGuard Pro subscription service could not be reached.");
  } finally {
    clearTimeout(timer);
  }
}

function isSecureApiUrl(url: URL): boolean {
  return (
    url.protocol === "https:" ||
    (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1"))
  );
}

function parsePlan(value: unknown): SubscriptionPlan {
  return value === "pro" || value === "team" || value === "enterprise" ? value : "free";
}

function parseState(value: unknown): SubscriptionState {
  return value === "active" || value === "trialing" || value === "past_due" || value === "canceled" ? value : "inactive";
}

function parseL3Usage(value: unknown): L3RequestUsage | undefined {
  if (!isRecord(value) || !isNonNegativeInteger(value.used) || !isNonNegativeInteger(value.limit)) {
    return undefined;
  }
  return {
    used: value.used,
    limit: value.limit,
    ...(typeof value.reset_at === "string" ? { resetAt: value.reset_at } : typeof value.resetAt === "string" ? { resetAt: value.resetAt } : {})
  };
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? [...new Set(value.filter((item): item is string => typeof item === "string" && item.length > 0))] : [];
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

import { createHash } from "crypto";
import type { DetectionLayer, Finding, FindingType, Severity } from "./types";

export type TelemetrySource = "vscode" | "cli";
export type TelemetryScope = "line" | "file" | "global" | "package";

export interface FalsePositiveTelemetryEvent {
  schemaVersion: 1;
  event: "false_positive_dismissal";
  source: TelemetrySource;
  scope: TelemetryScope;
  ruleFingerprint: string;
  findingType?: FindingType;
  detectionLayer?: DetectionLayer;
  severity?: Severity;
}

export interface ReportFalsePositiveTelemetryOptions {
  enabled: boolean;
  event: FalsePositiveTelemetryEvent;
  endpoint?: string;
  fetchImpl?: typeof globalThis.fetch;
  timeoutMs?: number;
}

export interface TelemetryDeliveryResult {
  attempted: boolean;
  sent: boolean;
}

const defaultEndpoint = "https://api.vibeguard.dev/v1/telemetry/false-positive";

/**
 * Builds an aggregate-only event. It intentionally omits source, paths, package names, authors, IDs, and free-form reasons.
 */
export function falsePositiveTelemetryEvent(
  finding: Pick<Finding, "detection_rule" | "type" | "detection_layer" | "severity">,
  source: TelemetrySource,
  scope: TelemetryScope
): FalsePositiveTelemetryEvent {
  return {
    schemaVersion: 1,
    event: "false_positive_dismissal",
    source,
    scope,
    ruleFingerprint: telemetryRuleFingerprint(finding.detection_rule),
    findingType: finding.type,
    detectionLayer: finding.detection_layer,
    severity: finding.severity
  };
}

export function cliFalsePositiveTelemetryEvent(rule: string, source: TelemetrySource, scope: TelemetryScope): FalsePositiveTelemetryEvent {
  return {
    schemaVersion: 1,
    event: "false_positive_dismissal",
    source,
    scope,
    ruleFingerprint: telemetryRuleFingerprint(rule)
  };
}

/**
 * Validates the only event schema accepted by a self-hosted feedback collector.
 * Unknown fields are rejected so source, paths, package names, and free-form text
 * cannot enter aggregate storage as the client evolves.
 */
export function parseFalsePositiveTelemetryEvent(value: unknown): FalsePositiveTelemetryEvent {
  if (!isRecord(value)) {
    throw new Error("Telemetry event must be a JSON object.");
  }
  const allowed = new Set([
    "schemaVersion",
    "event",
    "source",
    "scope",
    "ruleFingerprint",
    "findingType",
    "detectionLayer",
    "severity"
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error("Telemetry event contains unsupported fields.");
  }
  if (value.schemaVersion !== 1 || value.event !== "false_positive_dismissal") {
    throw new Error("Telemetry event schema is unsupported.");
  }
  if (!isTelemetrySource(value.source) || !isTelemetryScope(value.scope)) {
    throw new Error("Telemetry event has an invalid source or scope.");
  }
  if (typeof value.ruleFingerprint !== "string" || !/^[a-f0-9]{24}$/.test(value.ruleFingerprint)) {
    throw new Error("Telemetry event has an invalid rule fingerprint.");
  }
  if (value.findingType !== undefined && !isFindingType(value.findingType)) {
    throw new Error("Telemetry event has an invalid finding type.");
  }
  if (value.detectionLayer !== undefined && !isDetectionLayer(value.detectionLayer)) {
    throw new Error("Telemetry event has an invalid detection layer.");
  }
  if (value.severity !== undefined && !isSeverity(value.severity)) {
    throw new Error("Telemetry event has an invalid severity.");
  }
  return {
    schemaVersion: 1,
    event: "false_positive_dismissal",
    source: value.source,
    scope: value.scope,
    ruleFingerprint: value.ruleFingerprint,
    ...(value.findingType ? { findingType: value.findingType } : {}),
    ...(value.detectionLayer ? { detectionLayer: value.detectionLayer } : {}),
    ...(value.severity ? { severity: value.severity } : {})
  };
}

export function isFalsePositiveDismissalReason(reason: string | undefined): boolean {
  return /^false[\s_-]*positive(?:$|[\s(:])/i.test(reason?.trim() ?? "");
}

/** Sends an opt-in, privacy-minimized event. Network failures are intentionally non-fatal for developer workflows. */
export async function reportFalsePositiveTelemetry(options: ReportFalsePositiveTelemetryOptions): Promise<TelemetryDeliveryResult> {
  if (!options.enabled) {
    return { attempted: false, sent: false };
  }
  let endpoint: string;
  try {
    endpoint = normalizeTelemetryEndpoint(options.endpoint ?? defaultTelemetryEndpoint());
  } catch {
    return { attempted: false, sent: false };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 3000);
  try {
    const response = await (options.fetchImpl ?? globalThis.fetch)(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json"
      },
      body: JSON.stringify(options.event),
      redirect: "error",
      signal: controller.signal
    });
    return { attempted: true, sent: response.ok };
  } catch {
    return { attempted: true, sent: false };
  } finally {
    clearTimeout(timer);
  }
}

export function defaultTelemetryEndpoint(): string {
  return process.env.VIBEGUARD_TELEMETRY_ENDPOINT?.trim() || defaultEndpoint;
}

/** Stable, privacy-minimized identifier used by clients and self-hosted collectors. */
export function telemetryRuleFingerprint(rule: string): string {
  return createHash("sha256").update(rule.trim()).digest("hex").slice(0, 24);
}

function normalizeTelemetryEndpoint(value: string): string {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error("Telemetry endpoint must be an absolute URL.");
  }
  if (!isSecureEndpoint(endpoint) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error("Telemetry endpoint must use HTTPS outside localhost development and cannot include credentials, query parameters, or fragments.");
  }
  return endpoint.toString();
}

function isSecureEndpoint(endpoint: URL): boolean {
  return (
    endpoint.protocol === "https:" ||
    (endpoint.protocol === "http:" && (endpoint.hostname === "localhost" || endpoint.hostname === "127.0.0.1" || endpoint.hostname === "::1"))
  );
}

function isTelemetrySource(value: unknown): value is TelemetrySource {
  return value === "vscode" || value === "cli";
}

function isTelemetryScope(value: unknown): value is TelemetryScope {
  return value === "line" || value === "file" || value === "global" || value === "package";
}

function isFindingType(value: unknown): value is FindingType {
  return (
    value === "hallucinated_package" ||
    value === "hardcoded_secret" ||
    value === "insecure_config" ||
    value === "ai_pattern_error" ||
    value === "sql_injection" ||
    value === "xss" ||
    value === "ssrf" ||
    value === "path_traversal" ||
    value === "insecure_deserialization" ||
    value === "command_injection" ||
    value === "open_redirect" ||
    value === "information_leakage" ||
    value === "missing_security_measure" ||
    value === "other"
  );
}

function isDetectionLayer(value: unknown): value is DetectionLayer {
  return value === "L1" || value === "L2" || value === "L3";
}

function isSeverity(value: unknown): value is Severity {
  return value === "critical" || value === "high" || value === "medium" || value === "low" || value === "info";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

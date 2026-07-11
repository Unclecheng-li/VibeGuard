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
    ruleFingerprint: ruleFingerprint(finding.detection_rule),
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
    ruleFingerprint: ruleFingerprint(rule)
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

function ruleFingerprint(rule: string): string {
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

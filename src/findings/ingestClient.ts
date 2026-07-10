import { createFindingsIngestPayload } from "./ingest";
import type { RecordScanRunInput } from "./storage";

export interface UploadFindingsOptions {
  endpoint: string;
  token: string;
  scan: RecordScanRunInput;
  fetcher?: typeof fetch;
  timeoutMs?: number;
}

export interface UploadedFindingsResult {
  scanId: string;
  findingCount: number;
  activeCount: number;
  dismissedCount: number;
}

/** Uploads a completed scan to the separately-tokened private dashboard ingest endpoint. */
export async function uploadFindings(options: UploadFindingsOptions): Promise<UploadedFindingsResult> {
  const endpoint = normalizeEndpoint(options.endpoint);
  const token = options.token.trim();
  if (!token) {
    throw new Error("Findings ingest token must not be empty.");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
  try {
    const response = await (options.fetcher ?? fetch)(endpoint, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/json",
        "content-type": "application/json"
      },
      body: JSON.stringify(createFindingsIngestPayload(options.scan))
    });
    if (!response.ok) {
      throw new Error(`Findings upload failed with HTTP ${response.status}.`);
    }
    let result: unknown;
    try {
      result = await response.json();
    } catch {
      throw new Error("Findings upload returned an invalid JSON response.");
    }
    return parseUploadResult(result);
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("Findings upload timed out.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeEndpoint(value: string): string {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error("Findings endpoint must be an absolute http or https URL.");
  }
  if ((endpoint.protocol !== "http:" && endpoint.protocol !== "https:") || endpoint.username || endpoint.password) {
    throw new Error("Findings endpoint must be an absolute http or https URL without embedded credentials.");
  }
  if (endpoint.protocol === "http:" && !isLoopbackHost(endpoint.hostname)) {
    throw new Error("Findings endpoint must use HTTPS except for localhost development.");
  }
  return endpoint.toString();
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost" || normalized === "::1" || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}

function parseUploadResult(value: unknown): UploadedFindingsResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Findings upload returned an invalid response.");
  }
  const result = value as Record<string, unknown>;
  if (
    typeof result.scanId !== "string" ||
    !Number.isInteger(result.findingCount) ||
    !Number.isInteger(result.activeCount) ||
    !Number.isInteger(result.dismissedCount)
  ) {
    throw new Error("Findings upload returned an invalid response.");
  }
  return {
    scanId: result.scanId,
    findingCount: result.findingCount as number,
    activeCount: result.activeCount as number,
    dismissedCount: result.dismissedCount as number
  };
}

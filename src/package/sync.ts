import type { PackageRegistry } from "../types";

export type SyncableRegistry = Extract<PackageRegistry, "npm" | "pypi">;

export interface PackageSyncOptions {
  registry: SyncableRegistry;
  sourceUrl?: string;
  limit?: number;
  fetchImpl?: typeof fetch;
}

export interface PackageSyncResult {
  registry: SyncableRegistry;
  names: string[];
  sourceUrl: string;
  fetchedAt: number;
  totalAvailable?: number;
  truncated: boolean;
  format: "npm-all-docs" | "pypi-simple";
}

interface ParsedRemoteNames {
  names: string[];
  totalAvailable?: number;
  format: PackageSyncResult["format"];
}

export async function fetchPackageNames(options: PackageSyncOptions): Promise<PackageSyncResult> {
  const sourceUrl = buildSourceUrl(options.registry, options.sourceUrl, options.limit);
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(sourceUrl, {
    headers: {
      accept: options.registry === "npm" ? "application/json" : "text/html,application/xhtml+xml",
      "user-agent": "VibeGuard/0.1"
    }
  });

  if (!response.ok) {
    throw new Error(`Package sync failed for ${options.registry}: HTTP ${response.status}`);
  }

  const raw = await response.text();
  const parsed = options.registry === "npm" ? parseNpmAllDocs(raw) : parsePypiSimple(raw);
  const allNames = uniqueNames(parsed.names);
  const limitedNames = options.limit ? allNames.slice(0, options.limit) : allNames;
  const truncatedByLimit = Boolean(options.limit && allNames.length > options.limit);
  const truncatedByRegistryTotal = Boolean(parsed.totalAvailable && parsed.totalAvailable > limitedNames.length);

  return {
    registry: options.registry,
    names: limitedNames,
    sourceUrl,
    fetchedAt: Date.now(),
    totalAvailable: parsed.totalAvailable,
    truncated: truncatedByLimit || truncatedByRegistryTotal,
    format: parsed.format
  };
}

export function parseNpmAllDocs(raw: string): ParsedRemoteNames {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("npm package sync response was not an object.");
  }

  const object = parsed as Record<string, unknown>;
  if (!Array.isArray(object.rows)) {
    throw new Error("npm package sync response did not include rows.");
  }

  return {
    names: object.rows.map(rowPackageName).filter(isString),
    totalAvailable: typeof object.total_rows === "number" ? object.total_rows : undefined,
    format: "npm-all-docs"
  };
}

export function parsePypiSimple(raw: string): ParsedRemoteNames {
  const names: string[] = [];
  const anchorRegex = /<a\b[^>]*>(.*?)<\/a>/gis;
  for (const match of raw.matchAll(anchorRegex)) {
    const text = stripTags(match[1] ?? "");
    const packageName = decodeHtmlEntities(text).trim();
    if (packageName) {
      names.push(packageName);
    }
  }

  return {
    names,
    format: "pypi-simple"
  };
}

function buildSourceUrl(registry: SyncableRegistry, sourceUrl: string | undefined, limit: number | undefined): string {
  const base = sourceUrl ?? (registry === "npm" ? "https://replicate.npmjs.com/_all_docs" : "https://pypi.org/simple/");
  if (!limit || registry !== "npm") {
    return base;
  }

  try {
    const url = new URL(base);
    if (!url.searchParams.has("limit")) {
      url.searchParams.set("limit", String(limit));
    }
    return url.toString();
  } catch {
    const separator = base.includes("?") ? "&" : "?";
    return `${base}${separator}limit=${encodeURIComponent(String(limit))}`;
  }
}

function rowPackageName(value: unknown): string | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const row = value as Record<string, unknown>;
  const candidate = isString(row.id) ? row.id : isString(row.key) ? row.key : undefined;
  if (!candidate || candidate.startsWith("_design/")) {
    return undefined;
  }
  return candidate;
}

function uniqueNames(names: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const name of names) {
    const normalized = name.trim();
    const key = normalized.toLowerCase().replace(/_/g, "-");
    if (normalized && !seen.has(key)) {
      seen.add(key);
      result.push(normalized);
    }
  }
  return result;
}

function stripTags(value: string): string {
  return value.replace(/<[^>]+>/g, "");
}

function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x2F;/gi, "/");
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

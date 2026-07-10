import type { PackageRegistry } from "../types";

export type SyncableRegistry = PackageRegistry;

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
  pagesFetched?: number;
  truncated: boolean;
  format: "npm-all-docs" | "pypi-simple" | "cargo-crates" | "gomod-index" | "maven-search";
}

interface ParsedRemoteNames {
  names: string[];
  totalAvailable?: number;
  format: PackageSyncResult["format"];
}

export async function fetchPackageNames(options: PackageSyncOptions): Promise<PackageSyncResult> {
  if (isPaginatedRegistry(options.registry) && isHttpSourceUrl(options.sourceUrl ?? defaultSourceUrl(options.registry))) {
    return fetchPaginatedPackageNames(options);
  }

  const sourceUrl = buildSourceUrl(options.registry, options.sourceUrl, options.limit);
  const page = await fetchPackageNamePage(options.registry, sourceUrl, options.fetchImpl);
  const allNames = uniqueNames(page.parsed.names);
  const limitedNames = options.limit ? allNames.slice(0, options.limit) : allNames;
  const truncatedByLimit = Boolean(options.limit && allNames.length > options.limit);
  const truncatedByRegistryTotal = Boolean(page.parsed.totalAvailable && page.parsed.totalAvailable > limitedNames.length);

  return {
    registry: options.registry,
    names: limitedNames,
    sourceUrl,
    fetchedAt: Date.now(),
    totalAvailable: page.parsed.totalAvailable,
    pagesFetched: 1,
    truncated: truncatedByLimit || truncatedByRegistryTotal,
    format: page.parsed.format
  };
}

async function fetchPaginatedPackageNames(options: PackageSyncOptions): Promise<PackageSyncResult> {
  if (!isPaginatedRegistry(options.registry)) {
    throw new Error(`${options.registry} package sync does not support pagination.`);
  }
  const names: string[] = [];
  let totalAvailable: number | undefined;
  let format: PackageSyncResult["format"] | undefined;
  let sourceUrl = "";
  let pagesFetched = 0;
  const pageSize = paginatedPageSize(options.registry, options.limit);

  for (let pageIndex = 0; ; pageIndex += 1) {
    const nextUrl = buildPaginatedSourceUrl(options.registry, options.sourceUrl, pageSize, pageIndex);
    sourceUrl ||= nextUrl;
    const page = await fetchPackageNamePage(options.registry, nextUrl, options.fetchImpl);
    pagesFetched += 1;
    format = page.parsed.format;
    totalAvailable = page.parsed.totalAvailable ?? totalAvailable;
    names.push(...page.parsed.names);

    const uniqueCount = uniqueNames(names).length;
    const reachedLimit = Boolean(options.limit && uniqueCount >= options.limit);
    const reachedTotal = Boolean(totalAvailable !== undefined && uniqueCount >= totalAvailable);
    const shortPageWithoutTotal = totalAvailable === undefined && page.parsed.names.length < pageSize;
    if (reachedLimit || reachedTotal || shortPageWithoutTotal || page.parsed.names.length === 0) {
      break;
    }
  }

  const allNames = uniqueNames(names);
  const limitedNames = options.limit ? allNames.slice(0, options.limit) : allNames;
  const truncatedByLimit = Boolean(options.limit && allNames.length > options.limit);
  const truncatedByRegistryTotal = Boolean(totalAvailable && totalAvailable > limitedNames.length);

  return {
    registry: options.registry,
    names: limitedNames,
    sourceUrl,
    fetchedAt: Date.now(),
    totalAvailable,
    pagesFetched,
    truncated: truncatedByLimit || truncatedByRegistryTotal,
    format: format ?? defaultFormat(options.registry)
  };
}

async function fetchPackageNamePage(
  registry: SyncableRegistry,
  sourceUrl: string,
  fetcher: typeof fetch = fetch
): Promise<{ raw: string; parsed: ParsedRemoteNames }> {
  const response = await fetcher(sourceUrl, {
    headers: {
      accept: acceptHeader(registry),
      "user-agent": "VibeGuard/0.1"
    }
  });

  if (!response.ok) {
    throw new Error(`Package sync failed for ${registry}: HTTP ${response.status}`);
  }

  const raw = await response.text();
  return {
    raw,
    parsed: parseRegistryResponse(registry, raw)
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

export function parseCargoCrates(raw: string): ParsedRemoteNames {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Cargo package sync response was not an object.");
  }
  const object = parsed as Record<string, unknown>;
  if (!Array.isArray(object.crates)) {
    throw new Error("Cargo package sync response did not include crates.");
  }

  return {
    names: object.crates.map(cargoCrateName).filter(isString),
    totalAvailable: totalFromMeta(object.meta),
    format: "cargo-crates"
  };
}

export function parseGoModuleIndex(raw: string): ParsedRemoteNames {
  const names: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (parsed && typeof parsed === "object") {
        const candidate = (parsed as Record<string, unknown>).Path;
        if (isString(candidate)) {
          names.push(candidate);
        }
      }
    } catch {
      // Skip malformed rows so a single bad line does not discard the index.
    }
  }

  return {
    names,
    format: "gomod-index"
  };
}

export function parseMavenSearch(raw: string): ParsedRemoteNames {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Maven package sync response was not an object.");
  }
  const response = (parsed as Record<string, unknown>).response;
  if (!response || typeof response !== "object") {
    throw new Error("Maven package sync response did not include response.");
  }
  const object = response as Record<string, unknown>;
  if (!Array.isArray(object.docs)) {
    throw new Error("Maven package sync response did not include docs.");
  }

  return {
    names: object.docs.map(mavenCoordinate).filter(isString),
    totalAvailable: typeof object.numFound === "number" ? object.numFound : undefined,
    format: "maven-search"
  };
}

function parseRegistryResponse(registry: SyncableRegistry, raw: string): ParsedRemoteNames {
  switch (registry) {
    case "npm":
      return parseNpmAllDocs(raw);
    case "pypi":
      return parsePypiSimple(raw);
    case "cargo":
      return parseCargoCrates(raw);
    case "gomod":
      return parseGoModuleIndex(raw);
    case "maven":
      return parseMavenSearch(raw);
  }
}

function buildSourceUrl(registry: SyncableRegistry, sourceUrl: string | undefined, limit: number | undefined): string {
  const base = sourceUrl ?? defaultSourceUrl(registry);
  if (registry === "maven" && !limit && !sourceUrl) {
    return withQueryParam(base, "rows", "100");
  }
  if (!limit || registry === "pypi" || registry === "gomod") {
    return base;
  }

  const param = registry === "cargo" ? "per_page" : registry === "maven" ? "rows" : "limit";
  const value = registry === "cargo" ? String(Math.min(limit, 100)) : String(limit);
  return withQueryParam(base, param, value);
}

function buildPaginatedSourceUrl(
  registry: Extract<SyncableRegistry, "cargo" | "maven">,
  sourceUrl: string | undefined,
  pageSize: number,
  pageIndex: number
): string {
  const base = sourceUrl ?? defaultSourceUrl(registry);
  if (registry === "cargo") {
    return setQueryParams(base, {
      page: String(pageIndex + 1),
      per_page: String(pageSize)
    });
  }
  return setQueryParams(base, {
    start: String(pageIndex * pageSize),
    rows: String(pageSize)
  });
}

function withQueryParam(base: string, param: string, value: string): string {
  try {
    const url = new URL(base);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return base;
    }
    if (!url.searchParams.has(param)) {
      url.searchParams.set(param, value);
    }
    return url.toString();
  } catch {
    const separator = base.includes("?") ? "&" : "?";
    return `${base}${separator}${param}=${encodeURIComponent(value)}`;
  }
}

function setQueryParams(base: string, params: Record<string, string>): string {
  try {
    const url = new URL(base);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return base;
    }
    for (const [param, value] of Object.entries(params)) {
      url.searchParams.set(param, value);
    }
    return url.toString();
  } catch {
    const [prefix, query = ""] = base.split("?", 2);
    const pairs = query
      .split("&")
      .filter(Boolean)
      .filter((pair) => {
        const key = decodeURIComponent(pair.split("=", 1)[0] ?? "");
        if (key in params) {
          return false;
        }
        return true;
      });
    for (const [param, value] of Object.entries(params)) {
      pairs.push(`${encodeURIComponent(param)}=${encodeURIComponent(value)}`);
    }
    return pairs.length > 0 ? `${prefix}?${pairs.join("&")}` : prefix;
  }
}

function defaultSourceUrl(registry: SyncableRegistry): string {
  switch (registry) {
    case "npm":
      return "https://replicate.npmjs.com/_all_docs";
    case "pypi":
      return "https://pypi.org/simple/";
    case "cargo":
      return "https://crates.io/api/v1/crates";
    case "gomod":
      return "https://index.golang.org/index";
    case "maven":
      return "https://search.maven.org/solrsearch/select?q=*:*&wt=json";
  }
}

function isPaginatedRegistry(registry: SyncableRegistry): registry is "cargo" | "maven" {
  return registry === "cargo" || registry === "maven";
}

function paginatedPageSize(registry: "cargo" | "maven", limit: number | undefined): number {
  if (registry === "cargo") {
    return Math.min(limit ?? 100, 100);
  }
  return Math.min(limit ?? 100, 1000);
}

function isHttpSourceUrl(sourceUrl: string): boolean {
  try {
    const url = new URL(sourceUrl);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function defaultFormat(registry: SyncableRegistry): PackageSyncResult["format"] {
  switch (registry) {
    case "npm":
      return "npm-all-docs";
    case "pypi":
      return "pypi-simple";
    case "cargo":
      return "cargo-crates";
    case "gomod":
      return "gomod-index";
    case "maven":
      return "maven-search";
  }
}

function acceptHeader(registry: SyncableRegistry): string {
  return registry === "pypi" ? "text/html,application/xhtml+xml" : "application/json";
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

function cargoCrateName(value: unknown): string | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const crate = value as Record<string, unknown>;
  return isString(crate.id) ? crate.id : isString(crate.name) ? crate.name : undefined;
}

function totalFromMeta(value: unknown): number | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const total = (value as Record<string, unknown>).total;
  return typeof total === "number" ? total : undefined;
}

function mavenCoordinate(value: unknown): string | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const doc = value as Record<string, unknown>;
  if (isString(doc.g) && isString(doc.a)) {
    return `${doc.g}:${doc.a}`;
  }
  if (isString(doc.id) && doc.id.includes(":")) {
    return doc.id;
  }
  return undefined;
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

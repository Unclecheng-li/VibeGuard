import type { PackageIndexSyncMetadata, PackageRegistry } from "../types";

export type SyncableRegistry = PackageRegistry;

export interface PackageSyncOptions {
  registry: SyncableRegistry;
  sourceUrl?: string;
  limit?: number;
  fetchImpl?: typeof fetch;
  conditional?: PackageIndexSyncMetadata;
}

export interface PackageSyncResult {
  registry: SyncableRegistry;
  names: string[];
  sourceUrl: string;
  fetchedAt: number;
  totalAvailable?: number;
  pagesFetched?: number;
  truncated: boolean;
  format: "npm-all-docs" | "npm-changes" | "pypi-simple" | "cargo-crates" | "gomod-index" | "maven-search";
  notModified?: boolean;
  syncMetadata?: PackageIndexSyncMetadata;
}

export interface NpmPackageChangesOptions {
  sourceUrl?: string;
  since: string;
  fetchImpl?: typeof fetch;
}

export interface NpmPackageChangesResult {
  additions: string[];
  removals: string[];
  sourceUrl: string;
  lastSequence: string;
  pagesFetched: number;
  changesFetched: number;
}

export interface NpmChangeSnapshot {
  changeSourceUrl: string;
  changeSequence: string;
}

interface ParsedRemoteNames {
  names: string[];
  totalAvailable?: number;
  format: PackageSyncResult["format"];
}

interface ParsedNpmChanges {
  changes: { id: string; deleted: boolean }[];
  lastSequence: string;
  resultCount: number;
}

const NPM_CHANGES_PAGE_SIZE = 1000;

export async function fetchPackageNames(options: PackageSyncOptions): Promise<PackageSyncResult> {
  if (isPaginatedRegistry(options.registry) && isHttpSourceUrl(options.sourceUrl ?? defaultSourceUrl(options.registry))) {
    return fetchPaginatedPackageNames(options);
  }

  const sourceUrl = buildSourceUrl(options.registry, options.sourceUrl, options.limit);
  const conditional = conditionalForSource(options.conditional, sourceUrl);
  const page = await fetchPackageNamePage(options.registry, sourceUrl, options.fetchImpl, conditional);
  if (page.notModified) {
    return {
      registry: options.registry,
      names: [],
      sourceUrl,
      fetchedAt: Date.now(),
      pagesFetched: 0,
      truncated: false,
      format: defaultFormat(options.registry),
      notModified: true,
      syncMetadata: page.syncMetadata
    };
  }
  if (!page.parsed) {
    throw new Error(`Package sync returned no package data for ${options.registry}.`);
  }
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
    format: page.parsed.format,
    syncMetadata: page.syncMetadata
  };
}

export function canUseNpmIncrementalSync(metadata: PackageIndexSyncMetadata | undefined, sourceUrl?: string): boolean {
  const changeSourceUrl = npmChangesUrl(sourceUrl);
  return Boolean(
    changeSourceUrl &&
      metadata?.changeSourceUrl === changeSourceUrl &&
      typeof metadata.changeSequence === "string" &&
      metadata.changeSequence.length > 0
  );
}

export async function fetchNpmPackageChanges(options: NpmPackageChangesOptions): Promise<NpmPackageChangesResult> {
  const sourceUrl = npmChangesUrl(options.sourceUrl);
  if (!sourceUrl) {
    throw new Error("npm incremental sync requires an _all_docs source URL.");
  }

  const additions = new Set<string>();
  const removals = new Set<string>();
  let sequence = options.since;
  let pagesFetched = 0;
  let changesFetched = 0;

  for (;;) {
    const pageUrl = setQueryParams(sourceUrl, {
      since: sequence,
      limit: String(NPM_CHANGES_PAGE_SIZE)
    });
    const response = await (options.fetchImpl ?? fetch)(pageUrl, {
      headers: {
        accept: "application/json",
        "user-agent": "VibeGuard/0.1"
      }
    });
    if (!response.ok) {
      throw new Error(`npm incremental sync failed: HTTP ${response.status}`);
    }

    const page = parseNpmChanges(await response.text());
    pagesFetched += 1;
    changesFetched += page.changes.length;
    for (const change of page.changes) {
      if (change.deleted) {
        additions.delete(change.id);
        removals.add(change.id);
      } else {
        removals.delete(change.id);
        additions.add(change.id);
      }
    }

    if (page.resultCount < NPM_CHANGES_PAGE_SIZE) {
      return {
        additions: [...additions],
        removals: [...removals],
        sourceUrl,
        lastSequence: page.lastSequence,
        pagesFetched,
        changesFetched
      };
    }
    if (page.lastSequence === sequence) {
      throw new Error("npm incremental sync did not advance its change sequence.");
    }
    sequence = page.lastSequence;
  }
}

export async function fetchNpmChangeSnapshot(
  sourceUrl?: string,
  fetchImpl: typeof fetch = fetch
): Promise<NpmChangeSnapshot | undefined> {
  const changeSourceUrl = npmChangesUrl(sourceUrl);
  const snapshotUrl = npmSnapshotUrl(sourceUrl);
  if (!changeSourceUrl || !snapshotUrl) {
    return undefined;
  }
  const response = await fetchImpl(snapshotUrl, {
    headers: {
      accept: "application/json",
      "user-agent": "VibeGuard/0.1"
    }
  });
  if (!response.ok) {
    return undefined;
  }
  const parsed = JSON.parse(await response.text()) as unknown;
  if (!parsed || typeof parsed !== "object") {
    return undefined;
  }
  const sequence = sequenceValue((parsed as Record<string, unknown>).update_seq);
  return sequence ? { changeSourceUrl, changeSequence: sequence } : undefined;
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
    if (page.notModified || !page.parsed) {
      throw new Error(`Package sync returned no package data for ${options.registry}.`);
    }
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
  fetcher: typeof fetch = fetch,
  conditional?: PackageIndexSyncMetadata
): Promise<{ parsed?: ParsedRemoteNames; notModified: boolean; syncMetadata?: PackageIndexSyncMetadata }> {
  const headers: Record<string, string> = {
    accept: acceptHeader(registry),
    "user-agent": "VibeGuard/0.1"
  };
  if (conditional?.etag) {
    headers["if-none-match"] = conditional.etag;
  }
  if (conditional?.lastModified) {
    headers["if-modified-since"] = conditional.lastModified;
  }
  const response = await fetcher(sourceUrl, {
    headers
  });

  const syncMetadata = readSyncMetadata(response, sourceUrl, conditional);
  if (response.status === 304) {
    return { notModified: true, syncMetadata };
  }

  if (!response.ok) {
    throw new Error(`Package sync failed for ${registry}: HTTP ${response.status}`);
  }

  return {
    parsed: parseRegistryResponse(registry, await response.text()),
    notModified: false,
    syncMetadata
  };
}

function readSyncMetadata(response: Response, sourceUrl: string, previous?: PackageIndexSyncMetadata): PackageIndexSyncMetadata {
  const etag = response.headers?.get("etag") ?? previous?.etag;
  const lastModified = response.headers?.get("last-modified") ?? previous?.lastModified;
  return {
    sourceUrl,
    ...(etag ? { etag } : {}),
    ...(lastModified ? { lastModified } : {})
  };
}

function conditionalForSource(
  metadata: PackageIndexSyncMetadata | undefined,
  sourceUrl: string
): PackageIndexSyncMetadata | undefined {
  return metadata?.sourceUrl === sourceUrl ? metadata : undefined;
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

export function parseNpmChanges(raw: string): ParsedNpmChanges {
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("npm incremental sync response was not an object.");
  }
  const object = parsed as Record<string, unknown>;
  if (!Array.isArray(object.results)) {
    throw new Error("npm incremental sync response did not include results.");
  }
  const lastSequence = sequenceValue(object.last_seq);
  if (!lastSequence) {
    throw new Error("npm incremental sync response did not include last_seq.");
  }
  return {
    changes: object.results
      .map((result) => {
        if (!result || typeof result !== "object") {
          return undefined;
        }
        const row = result as Record<string, unknown>;
        return isString(row.id) && !row.id.startsWith("_design/")
          ? { id: row.id, deleted: row.deleted === true }
          : undefined;
      })
      .filter((change): change is { id: string; deleted: boolean } => Boolean(change)),
    lastSequence,
    resultCount: object.results.length
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

function npmChangesUrl(sourceUrl?: string): string | undefined {
  try {
    const url = new URL(sourceUrl ?? defaultSourceUrl("npm"));
    if (url.protocol !== "http:" && url.protocol !== "https:" || !/\/_all_docs\/?$/.test(url.pathname)) {
      return undefined;
    }
    url.pathname = url.pathname.replace(/\/_all_docs\/?$/, "/_changes");
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return undefined;
  }
}

function npmSnapshotUrl(sourceUrl?: string): string | undefined {
  try {
    const url = new URL(sourceUrl ?? defaultSourceUrl("npm"));
    if (url.protocol !== "http:" && url.protocol !== "https:" || !/\/_all_docs\/?$/.test(url.pathname)) {
      return undefined;
    }
    url.pathname = url.pathname.replace(/\/_all_docs\/?$/, "/");
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return undefined;
  }
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

function sequenceValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) {
    return value;
  }
  return typeof value === "number" && Number.isFinite(value) ? String(value) : undefined;
}

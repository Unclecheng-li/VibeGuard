import type { PackageIndexEntry, PackageRegistry, VibeGuardConfig } from "../types";
import type { PackageStorage } from "./storage";
import { fetchPackageNames, type PackageSyncResult } from "./sync";

export const LIGHTWEIGHT_PACKAGE_LIMIT = 100000;
export const CARGO_LIGHTWEIGHT_PACKAGE_LIMIT = 100;

export type ConfiguredPackageSyncReason = "forced" | "missing" | "stale" | "partial-needs-full" | "fresh";

export interface PackageIndexSyncDecision {
  due: boolean;
  reason: ConfiguredPackageSyncReason;
  ageMs?: number;
  intervalMs: number;
}

export interface ConfiguredPackageSyncOutcome {
  registry: PackageRegistry;
  status: "synced" | "skipped" | "failed";
  reason: ConfiguredPackageSyncReason;
  requestedCoverage: "partial" | "full";
  effectiveCoverage?: "partial" | "full";
  coverage?: "partial" | "full";
  packageCount?: number;
  updatedAt?: number;
  imported?: number;
  pagesFetched?: number;
  truncated?: boolean;
  totalAvailable?: number;
  sourceUrl?: string;
  format?: PackageSyncResult["format"];
  limit?: number;
  error?: string;
}

export interface ConfiguredPackageSyncOptions {
  config: VibeGuardConfig;
  storage: PackageStorage;
  fetchImpl?: typeof fetch;
  now?: number;
  force?: boolean;
  limit?: number;
  sourceUrls?: Partial<Record<PackageRegistry, string>>;
  continueOnError?: boolean;
}

export interface ConfiguredPackageSyncResult {
  storage: PackageStorage["kind"];
  path?: string;
  updateInterval: VibeGuardConfig["package_cache"]["update_interval"];
  intervalMs: number;
  lightweightMode: boolean;
  results: ConfiguredPackageSyncOutcome[];
}

export async function syncConfiguredPackageIndexes(
  options: ConfiguredPackageSyncOptions
): Promise<ConfiguredPackageSyncResult> {
  const now = options.now ?? Date.now();
  const stats = new Map((await options.storage.packageIndex.stats()).map((entry) => [entry.registry, entry]));
  const intervalMs = packageSyncIntervalMs(options.config.package_cache.update_interval);
  const requestedCoverage = options.config.package_cache.lightweight_mode ? "partial" : "full";
  const results: ConfiguredPackageSyncOutcome[] = [];
  const continueOnError = options.continueOnError ?? true;

  for (const registry of uniqueRegistries(options.config.package_cache.languages)) {
    const existingEntry = stats.get(registry);
    const decision = shouldSyncPackageIndex(existingEntry, options.config, now, Boolean(options.force));
    const limit = configuredPackageSyncLimit(options.config, registry, options.limit);

    if (!decision.due && existingEntry) {
      results.push({
        registry,
        status: "skipped",
        reason: decision.reason,
        requestedCoverage,
        coverage: existingEntry.coverage,
        packageCount: existingEntry.packageCount,
        updatedAt: existingEntry.updatedAt,
        limit
      });
      continue;
    }

    try {
      const syncResult = await fetchPackageNames({
        registry,
        sourceUrl: options.sourceUrls?.[registry],
        limit,
        fetchImpl: options.fetchImpl
      });
      const effectiveCoverage = requestedCoverage === "full" && !syncResult.truncated ? "full" : "partial";
      const entry = await options.storage.packageIndex.importPackageNames(
        registry,
        syncResult.names,
        effectiveCoverage
      );
      results.push({
        registry,
        status: "synced",
        reason: decision.reason,
        requestedCoverage,
        effectiveCoverage,
        coverage: entry.coverage,
        packageCount: entry.packageCount,
        updatedAt: entry.updatedAt,
        imported: syncResult.names.length,
        pagesFetched: syncResult.pagesFetched,
        truncated: syncResult.truncated,
        totalAvailable: syncResult.totalAvailable,
        sourceUrl: syncResult.sourceUrl,
        format: syncResult.format,
        limit
      });
    } catch (error) {
      if (!continueOnError) {
        throw error;
      }
      results.push({
        registry,
        status: "failed",
        reason: decision.reason,
        requestedCoverage,
        limit,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  return {
    storage: options.storage.kind,
    path: options.storage.sqlitePath ?? options.storage.indexPath,
    updateInterval: options.config.package_cache.update_interval,
    intervalMs,
    lightweightMode: options.config.package_cache.lightweight_mode,
    results
  };
}

export function shouldSyncPackageIndex(
  entry: PackageIndexEntry | undefined,
  config: VibeGuardConfig,
  now = Date.now(),
  force = false
): PackageIndexSyncDecision {
  const intervalMs = packageSyncIntervalMs(config.package_cache.update_interval);
  if (force) {
    return { due: true, reason: "forced", intervalMs };
  }
  if (!entry) {
    return { due: true, reason: "missing", intervalMs };
  }

  const ageMs = Math.max(0, now - entry.updatedAt);
  if (!config.package_cache.lightweight_mode && entry.coverage !== "full") {
    return { due: true, reason: "partial-needs-full", ageMs, intervalMs };
  }
  if (ageMs >= intervalMs) {
    return { due: true, reason: "stale", ageMs, intervalMs };
  }
  return { due: false, reason: "fresh", ageMs, intervalMs };
}

export function packageSyncIntervalMs(updateInterval: VibeGuardConfig["package_cache"]["update_interval"]): number {
  return updateInterval === "weekly" ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
}

export function configuredPackageSyncLimit(
  config: VibeGuardConfig,
  registry: PackageRegistry,
  overrideLimit?: number
): number | undefined {
  if (overrideLimit !== undefined) {
    return overrideLimit;
  }
  if (!config.package_cache.lightweight_mode) {
    return undefined;
  }
  return registry === "cargo" ? CARGO_LIGHTWEIGHT_PACKAGE_LIMIT : LIGHTWEIGHT_PACKAGE_LIMIT;
}

export function selectConfiguredPackageSyncRegistries(
  configuredRegistries: PackageRegistry[],
  detectedRegistries: PackageRegistry[]
): PackageRegistry[] {
  const configured = uniqueRegistries(configuredRegistries);
  const detected = uniqueRegistries(detectedRegistries);
  const detectedConfigured = detected.filter((registry) => configured.includes(registry));
  return detectedConfigured.length > 0 ? detectedConfigured : configured;
}

function uniqueRegistries(registries: PackageRegistry[]): PackageRegistry[] {
  return [...new Set(registries)];
}

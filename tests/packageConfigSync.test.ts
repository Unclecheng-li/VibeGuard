import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cloneDefaultConfig } from "../src/config";
import { JsonPackageNameIndex, type PackageCacheStore } from "../src/package/cache";
import { isSqliteAvailable, SqlitePackageNameIndex } from "../src/package/sqliteStore";
import {
  CARGO_LIGHTWEIGHT_PACKAGE_LIMIT,
  LIGHTWEIGHT_PACKAGE_LIMIT,
  configuredPackageSyncLimit,
  selectConfiguredPackageSyncRegistries,
  shouldUpgradePackageCacheInBackground,
  shouldSyncPackageIndex,
  syncConfiguredPackageIndexes,
  syncConfiguredPackageIndexesInBackground
} from "../src/package/configSync";
import type { ConfiguredPackageSyncProgress } from "../src/package/configSync";
import type { PackageIndexStore, PackageStorage } from "../src/package/storage";
import { fetchNpmPackageChanges, fetchPackageNames } from "../src/package/sync";
import type {
  PackageIndexEntry,
  PackageIndexSyncMetadata,
  PackageRegistry,
  PackageResolution,
  VibeGuardConfig
} from "../src/types";

test("syncs missing configured package indexes and skips fresh indexes", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  index.seed("npm", ["react"], "partial", now - 60_000);
  const fetchedUrls: string[] = [];
  const progress: ConfiguredPackageSyncProgress[] = [];
  const config = testConfig({
    languages: ["npm", "maven"],
    update_interval: "daily",
    lightweight_mode: true
  });

  const result = await syncConfiguredPackageIndexes({
    config,
    storage: createMemoryStorage(index),
    now,
    sourceUrls: {
      maven: "https://example.test/solrsearch/select?q=*:*&wt=json"
    },
    fetchImpl: async (url) => {
      fetchedUrls.push(String(url));
      return response(
        JSON.stringify({
          response: {
            numFound: 1,
            docs: [{ g: "junit", a: "junit" }]
          }
        })
      );
    },
    onProgress: (event) => progress.push(event)
  });

  assert.equal(result.lightweightMode, true);
  assert.equal(result.results.length, 2);
  assert.equal(result.results[0].registry, "npm");
  assert.equal(result.results[0].status, "skipped");
  assert.equal(result.results[0].reason, "fresh");
  assert.equal(result.results[1].registry, "maven");
  assert.equal(result.results[1].status, "synced");
  assert.equal(result.results[1].reason, "missing");
  assert.equal(result.results[1].requestedCoverage, "partial");
  assert.equal(result.results[1].limit, LIGHTWEIGHT_PACKAGE_LIMIT);
  assert.equal(await index.get("maven", "junit:junit"), true);
  assert.match(fetchedUrls[0], /rows=1000/);
  assert.match(fetchedUrls[0], /start=0/);
  assert.deepEqual(progress, [
    { registry: "npm", completed: 0, total: 2, phase: "starting" },
    { registry: "npm", completed: 1, total: 2, phase: "completed", status: "skipped" },
    { registry: "maven", completed: 1, total: 2, phase: "starting" },
    { registry: "maven", completed: 2, total: 2, phase: "completed", status: "synced" }
  ]);
});

test("full configured package sync refreshes partial indexes before they expire", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  index.seed("npm", ["react"], "partial", now - 60_000);
  const config = testConfig({
    languages: ["npm"],
    update_interval: "weekly",
    lightweight_mode: false
  });

  const result = await syncConfiguredPackageIndexes({
    config,
    storage: createMemoryStorage(index),
    now,
    fetchImpl: async () =>
      response(
        JSON.stringify({
          total_rows: 2,
          rows: [{ id: "react" }, { id: "express" }]
        })
      )
  });

  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].status, "synced");
  assert.equal(result.results[0].reason, "partial-needs-full");
  assert.equal(result.results[0].requestedCoverage, "full");
  assert.equal(result.results[0].effectiveCoverage, "full");
  assert.equal(result.results[0].limit, undefined);
  assert.equal(await index.coverage("npm"), "full");
  assert.equal(await index.get("npm", "missing-package"), false);
});

test("background package sync upgrades a successful lightweight index to full coverage", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  const requestedUrls: string[] = [];
  const tiers: string[] = [];

  const result = await syncConfiguredPackageIndexesInBackground({
    config: testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: true }),
    storage: createMemoryStorage(index),
    now,
    upgradeFull: true,
    fetchImpl: async (url) => {
      requestedUrls.push(String(url));
      if (String(url).includes("/_all_docs")) {
        return response(JSON.stringify({ total_rows: 1, rows: [{ id: "react" }] }));
      }
      return response(JSON.stringify({ update_seq: "1-g" }));
    },
    onTierStart: (tier) => tiers.push(tier)
  });

  assert.deepEqual(tiers, ["lightweight", "full"]);
  assert.deepEqual(result.tiers.map((entry) => entry.tier), ["lightweight", "full"]);
  assert.equal(result.tiers[0]?.result.results[0]?.coverage, "partial");
  assert.equal(result.tiers[1]?.result.results[0]?.coverage, "full");
  assert.equal(await index.coverage("npm"), "full");
  assert.equal(requestedUrls.some((url) => /_all_docs\?limit=100000/.test(url)), true);
  assert.equal(requestedUrls.some((url) => /_all_docs\/?$/.test(url)), true);
});

test("background full upgrades remain opt-out for lightweight package caches", () => {
  const enabled = testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: true });
  const disabled = testConfig({
    languages: ["npm"],
    update_interval: "daily",
    lightweight_mode: true,
    background_full_sync: false
  });

  assert.equal(shouldUpgradePackageCacheInBackground(enabled), true);
  assert.equal(shouldUpgradePackageCacheInBackground(disabled), false);
  assert.equal(shouldUpgradePackageCacheInBackground(testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: false })), false);
});

test("package sync decisions respect intervals, force, and lightweight limits", () => {
  const now = 1_700_000_000_000;
  const dailyConfig = testConfig({
    languages: ["npm"],
    update_interval: "daily",
    lightweight_mode: true
  });
  const weeklyConfig = testConfig({
    languages: ["cargo"],
    update_interval: "weekly",
    lightweight_mode: true
  });
  const entry: PackageIndexEntry = {
    registry: "npm",
    coverage: "partial",
    updatedAt: now - 60_000,
    packageCount: 1
  };

  assert.deepEqual(shouldSyncPackageIndex(undefined, dailyConfig, now).reason, "missing");
  assert.equal(shouldSyncPackageIndex(entry, dailyConfig, now).due, false);
  assert.equal(shouldSyncPackageIndex(entry, dailyConfig, now, true).reason, "forced");
  assert.equal(shouldSyncPackageIndex({ ...entry, updatedAt: now - 25 * 60 * 60 * 1000 }, dailyConfig, now).reason, "stale");
  assert.equal(configuredPackageSyncLimit(dailyConfig, "npm"), LIGHTWEIGHT_PACKAGE_LIMIT);
  assert.equal(configuredPackageSyncLimit(weeklyConfig, "cargo"), CARGO_LIGHTWEIGHT_PACKAGE_LIMIT);
  assert.equal(configuredPackageSyncLimit(dailyConfig, "npm", 42), 42);
});

test("refreshes stale indexes from a conditional 304 response without reimporting packages", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  index.seed("npm", ["react"], "partial", now - 25 * 60 * 60 * 1000, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs?limit=100000",
    etag: "\"npm-v1\"",
    lastModified: "Mon, 01 Jan 2024 00:00:00 GMT"
  });
  let requestHeaders: HeadersInit | undefined;

  const result = await syncConfiguredPackageIndexes({
    config: testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: true }),
    storage: createMemoryStorage(index),
    now,
    fetchImpl: async (_url, init) => {
      requestHeaders = init?.headers;
      return new Response(null, { status: 304, headers: { etag: "\"npm-v1\"" } });
    }
  });

  const headers = new Headers(requestHeaders);
  assert.equal(headers.get("if-none-match"), "\"npm-v1\"");
  assert.equal(headers.get("if-modified-since"), "Mon, 01 Jan 2024 00:00:00 GMT");
  assert.equal(result.results[0].status, "skipped");
  assert.equal(result.results[0].reason, "not-modified");
  assert.equal(result.results[0].imported, undefined);
  assert.equal(index.importCalls, 0);
  assert.equal(await index.get("npm", "react"), true);
  assert.equal((await index.stats())[0]?.updatedAt, now);
});

test("does not reuse a registry validator after the package source URL changes", async () => {
  let requestHeaders: HeadersInit | undefined;
  await fetchPackageNames({
    registry: "npm",
    sourceUrl: "https://mirror.example.test/npm/_all_docs",
    conditional: {
      sourceUrl: "https://replicate.npmjs.com/_all_docs",
      etag: "\"old-validator\"",
      lastModified: "Mon, 01 Jan 2024 00:00:00 GMT"
    },
    fetchImpl: async (_url, init) => {
      requestHeaders = init?.headers;
      return response(JSON.stringify({ total_rows: 1, rows: [{ id: "react" }] }));
    }
  });

  const headers = new Headers(requestHeaders);
  assert.equal(headers.get("if-none-match"), null);
  assert.equal(headers.get("if-modified-since"), null);
});

test("paginates npm change batches and folds conflicting package events", async () => {
  const requestedSequences: string[] = [];
  const result = await fetchNpmPackageChanges({
    since: "100",
    fetchImpl: async (url) => {
      const sequence = new URL(String(url)).searchParams.get("since") ?? "";
      requestedSequences.push(sequence);
      if (sequence === "100") {
        return response(
          JSON.stringify({
            results: Array.from({ length: 1000 }, (_, index) => ({ id: `package-${index}` })),
            last_seq: "1100"
          })
        );
      }
      return response(
        JSON.stringify({
          results: [{ id: "package-1", deleted: true }, { id: "vite" }],
          last_seq: "1102"
        })
      );
    }
  });

  assert.deepEqual(requestedSequences, ["100", "1100"]);
  assert.equal(result.pagesFetched, 2);
  assert.equal(result.changesFetched, 1002);
  assert.equal(result.lastSequence, "1102");
  assert.equal(result.additions.includes("package-1"), false);
  assert.equal(result.additions.includes("vite"), true);
  assert.deepEqual(result.removals, ["package-1"]);
});

test("captures a npm change snapshot with the initial full package sync", async () => {
  const index = new MemoryPackageIndex(1_700_000_000_000);
  const requestedUrls: string[] = [];

  await syncConfiguredPackageIndexes({
    config: testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: true }),
    storage: createMemoryStorage(index),
    fetchImpl: async (url) => {
      requestedUrls.push(String(url));
      const parsed = new URL(String(url));
      return response(
        parsed.pathname === "/"
          ? JSON.stringify({ update_seq: 100 })
          : JSON.stringify({ total_rows: 1, rows: [{ id: "react" }] })
      );
    }
  });

  assert.equal(requestedUrls.some((url) => new URL(url).pathname === "/"), true);
  const metadata = (await index.stats())[0]?.syncMetadata;
  assert.equal(metadata?.changeSourceUrl, "https://replicate.npmjs.com/_changes");
  assert.equal(metadata?.changeSequence, "100");
});

test("applies stale npm change entries without refetching the complete package index", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  index.seed("npm", ["react", "express"], "partial", now - 25 * 60 * 60 * 1000, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs?limit=100000",
    changeSourceUrl: "https://replicate.npmjs.com/_changes",
    changeSequence: "100"
  });
  const requestedUrls: string[] = [];

  const result = await syncConfiguredPackageIndexes({
    config: testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: true }),
    storage: createMemoryStorage(index),
    now,
    fetchImpl: async (url) => {
      requestedUrls.push(String(url));
      return response(
        JSON.stringify({
          results: [{ id: "vite" }, { id: "express", deleted: true }],
          last_seq: 102
        })
      );
    }
  });

  const outcome = result.results[0];
  assert.equal(outcome?.status, "synced");
  assert.equal(outcome?.incremental, true);
  assert.equal(outcome?.additions, 1);
  assert.equal(outcome?.removals, 1);
  assert.equal(outcome?.changesFetched, 2);
  assert.equal(index.importCalls, 0);
  assert.equal(index.changeCalls, 1);
  assert.equal(await index.get("npm", "vite"), true);
  assert.equal(await index.get("npm", "express"), undefined);
  assert.equal((await index.stats())[0]?.syncMetadata?.changeSequence, "102");
  assert.equal(requestedUrls.every((url) => new URL(url).pathname === "/_changes"), true);
});

test("does not apply an npm change sequence after the configured mirror changes", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  index.seed("npm", ["react"], "partial", now - 25 * 60 * 60 * 1000, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs?limit=100000",
    changeSourceUrl: "https://replicate.npmjs.com/_changes",
    changeSequence: "100"
  });
  const requestedUrls: string[] = [];

  const result = await syncConfiguredPackageIndexes({
    config: testConfig({ languages: ["npm"], update_interval: "daily", lightweight_mode: true }),
    storage: createMemoryStorage(index),
    now,
    sourceUrls: { npm: "https://mirror.example.test/npm/_all_docs" },
    fetchImpl: async (url) => {
      requestedUrls.push(String(url));
      return response(
        new URL(String(url)).pathname === "/npm/"
          ? JSON.stringify({ update_seq: 200 })
          : JSON.stringify({ total_rows: 1, rows: [{ id: "vite" }] })
      );
    }
  });

  assert.equal(result.results[0]?.incremental, undefined);
  assert.equal(index.importCalls, 1);
  assert.equal(index.changeCalls, 0);
  assert.equal(requestedUrls.some((url) => new URL(url).pathname.endsWith("/_changes")), false);
  assert.equal((await index.stats())[0]?.syncMetadata?.changeSourceUrl, "https://mirror.example.test/npm/_changes");
});

test("persists conditional sync metadata in the JSON package index", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-sync-metadata-"));
  const filePath = path.join(directory, "package-index.json");
  const first = new JsonPackageNameIndex(filePath);
  await first.importPackageNames("npm", ["react"], "partial", {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    etag: "\"npm-v1\""
  });

  const reopened = new JsonPackageNameIndex(filePath);
  const initial = (await reopened.stats())[0];
  assert.deepEqual(initial?.syncMetadata, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    etag: "\"npm-v1\""
  });
  const refreshed = await reopened.touch("npm", { lastModified: "Mon, 01 Jan 2024 00:00:00 GMT" });
  assert.deepEqual(refreshed.syncMetadata, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    etag: "\"npm-v1\"",
    lastModified: "Mon, 01 Jan 2024 00:00:00 GMT"
  });
});

test("stores gzip package indexes compressed and reopens them", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-gzip-index-"));
  const filePath = path.join(directory, "package-index.json.gz");
  const first = new JsonPackageNameIndex(filePath);
  await first.importPackageNames("npm", ["react"], "partial");

  const raw = await fs.readFile(filePath);
  assert.deepEqual([...raw.subarray(0, 2)], [0x1f, 0x8b]);

  const reopened = new JsonPackageNameIndex(filePath);
  assert.equal(await reopened.get("npm", "react"), true);
});

test("persists JSON package index additions and removals from a change batch", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-index-changes-"));
  const filePath = path.join(directory, "package-index.json");
  const index = new JsonPackageNameIndex(filePath);
  await index.importPackageNames("npm", ["react", "express"], "full", {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    changeSourceUrl: "https://replicate.npmjs.com/_changes",
    changeSequence: "100"
  });
  await index.applyPackageNameChanges("npm", ["vite"], ["express"], { changeSequence: "102" });

  assert.equal(await index.get("npm", "vite"), true);
  assert.equal(await index.get("npm", "express"), false);
  const reopened = new JsonPackageNameIndex(filePath);
  assert.equal(await reopened.get("npm", "vite"), true);
  assert.equal(await reopened.get("npm", "express"), false);
  assert.equal((await reopened.stats())[0]?.syncMetadata?.changeSequence, "102");
});

test("migrates a legacy plain JSON package index when saving the gzip default", async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-gzip-migration-"));
  const legacyFilePath = path.join(directory, "package-index.json");
  const compressedFilePath = `${legacyFilePath}.gz`;
  await fs.writeFile(
    legacyFilePath,
    JSON.stringify({
      registries: {
        npm: { coverage: "partial", updatedAt: 1_700_000_000_000, packages: ["react"] }
      }
    }),
    "utf8"
  );

  const migrated = new JsonPackageNameIndex(compressedFilePath);
  assert.equal(await migrated.get("npm", "react"), true);
  await migrated.importPackageNames("npm", ["express"], "partial");

  const compressed = await fs.readFile(compressedFilePath);
  assert.deepEqual([...compressed.subarray(0, 2)], [0x1f, 0x8b]);
  const reopened = new JsonPackageNameIndex(compressedFilePath);
  assert.equal(await reopened.get("npm", "react"), true);
  assert.equal(await reopened.get("npm", "express"), true);
});

test("persists conditional sync metadata in the SQLite package index", async (context) => {
  if (!isSqliteAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-sync-metadata-sqlite-"));
  const databasePath = path.join(directory, "packages.db");
  const first = new SqlitePackageNameIndex(databasePath);
  await first.importPackageNames("npm", ["react"], "partial", {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    etag: "\"npm-v1\""
  });
  first.close();

  const reopened = new SqlitePackageNameIndex(databasePath);
  const initial = (await reopened.stats())[0];
  assert.deepEqual(initial?.syncMetadata, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    etag: "\"npm-v1\""
  });
  const refreshed = await reopened.touch("npm", { lastModified: "Mon, 01 Jan 2024 00:00:00 GMT" });
  assert.deepEqual(refreshed.syncMetadata, {
    sourceUrl: "https://replicate.npmjs.com/_all_docs",
    etag: "\"npm-v1\"",
    lastModified: "Mon, 01 Jan 2024 00:00:00 GMT"
  });
  await reopened.applyPackageNameChanges("npm", ["vite"], ["react"], {
    changeSourceUrl: "https://replicate.npmjs.com/_changes",
    changeSequence: "100"
  });
  assert.equal(await reopened.get("npm", "react"), undefined);
  assert.equal(await reopened.get("npm", "vite"), true);
  assert.equal((await reopened.stats())[0]?.syncMetadata?.changeSequence, "100");
  reopened.close();
});

test("prioritizes detected package registries while retaining configured background sync", () => {
  assert.deepEqual(selectConfiguredPackageSyncRegistries(["npm", "pypi", "maven"], ["maven", "npm", "cargo"]), ["maven", "npm", "pypi"]);
  assert.deepEqual(selectConfiguredPackageSyncRegistries(["pypi"], ["npm"]), ["pypi"]);
  assert.deepEqual(selectConfiguredPackageSyncRegistries(["npm", "npm", "maven"], []), ["npm", "maven"]);
  assert.deepEqual(selectConfiguredPackageSyncRegistries([], ["npm"]), []);
});

function testConfig(
  packageCache: Omit<VibeGuardConfig["package_cache"], "background_full_sync"> &
    Partial<Pick<VibeGuardConfig["package_cache"], "background_full_sync">>
): VibeGuardConfig {
  const defaults = cloneDefaultConfig();
  return {
    ...defaults,
    package_cache: {
      ...defaults.package_cache,
      ...packageCache
    }
  };
}

function createMemoryStorage(index: MemoryPackageIndex): PackageStorage {
  return {
    kind: "json",
    cache: memoryCache,
    packageIndex: index,
    indexPath: "memory-package-index.json"
  };
}

const memoryCache: PackageCacheStore = {
  async get(): Promise<PackageResolution | undefined> {
    return undefined;
  },
  async set(): Promise<void> {}
};

class MemoryPackageIndex implements PackageIndexStore {
  private readonly entries = new Map<
    PackageRegistry,
    { coverage: "partial" | "full"; updatedAt: number; packages: Set<string>; syncMetadata?: PackageIndexSyncMetadata }
  >();
  importCalls = 0;
  changeCalls = 0;

  constructor(private readonly now: number) {}

  seed(
    registry: PackageRegistry,
    packageNames: string[],
    coverage: "partial" | "full",
    updatedAt: number,
    syncMetadata?: PackageIndexSyncMetadata
  ): void {
    this.entries.set(registry, {
      coverage,
      updatedAt,
      packages: new Set(packageNames.map(normalizePackageName)),
      ...(syncMetadata ? { syncMetadata } : {})
    });
  }

  async get(registry: PackageRegistry, packageName: string): Promise<boolean | undefined> {
    const entry = this.entries.get(registry);
    if (!entry) {
      return undefined;
    }
    if (entry.packages.has(normalizePackageName(packageName))) {
      return true;
    }
    return entry.coverage === "full" ? false : undefined;
  }

  async coverage(registry: PackageRegistry): Promise<"partial" | "full" | undefined> {
    return this.entries.get(registry)?.coverage;
  }

  async importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial",
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry> {
    this.importCalls += 1;
    const existing = this.entries.get(registry);
    const packages = coverage === "full" ? new Set<string>() : new Set(existing?.packages ?? []);
    for (const packageName of packageNames) {
      packages.add(normalizePackageName(packageName));
    }
    this.entries.set(registry, {
      coverage,
      updatedAt: this.now,
      packages,
      syncMetadata: mergeSyncMetadata(existing?.syncMetadata, syncMetadata)
    });
    return {
      registry,
      coverage,
      updatedAt: this.now,
      packageCount: packages.size,
      ...(mergeSyncMetadata(existing?.syncMetadata, syncMetadata)
        ? { syncMetadata: mergeSyncMetadata(existing?.syncMetadata, syncMetadata) }
        : {})
    };
  }

  async touch(registry: PackageRegistry, syncMetadata?: PackageIndexSyncMetadata): Promise<PackageIndexEntry> {
    const existing = this.entries.get(registry);
    if (!existing) {
      throw new Error(`Cannot refresh missing ${registry} package index.`);
    }
    const merged = mergeSyncMetadata(existing.syncMetadata, syncMetadata);
    this.entries.set(registry, { ...existing, updatedAt: this.now, ...(merged ? { syncMetadata: merged } : {}) });
    return {
      registry,
      coverage: existing.coverage,
      updatedAt: this.now,
      packageCount: existing.packages.size,
      ...(merged ? { syncMetadata: merged } : {})
    };
  }

  async applyPackageNameChanges(
    registry: PackageRegistry,
    additions: Iterable<string>,
    removals: Iterable<string>,
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry> {
    this.changeCalls += 1;
    const existing = this.entries.get(registry);
    if (!existing) {
      throw new Error(`Cannot apply changes to missing ${registry} package index.`);
    }
    const packages = new Set(existing.packages);
    for (const packageName of additions) {
      packages.add(normalizePackageName(packageName));
    }
    for (const packageName of removals) {
      packages.delete(normalizePackageName(packageName));
    }
    const merged = mergeSyncMetadata(existing.syncMetadata, syncMetadata);
    this.entries.set(registry, {
      coverage: existing.coverage,
      updatedAt: this.now,
      packages,
      ...(merged ? { syncMetadata: merged } : {})
    });
    return {
      registry,
      coverage: existing.coverage,
      updatedAt: this.now,
      packageCount: packages.size,
      ...(merged ? { syncMetadata: merged } : {})
    };
  }

  async stats(): Promise<PackageIndexEntry[]> {
    return [...this.entries.entries()]
      .map(([registry, entry]) => ({
        registry,
        coverage: entry.coverage,
        updatedAt: entry.updatedAt,
        packageCount: entry.packages.size,
        ...(entry.syncMetadata ? { syncMetadata: entry.syncMetadata } : {})
      }))
      .sort((a, b) => a.registry.localeCompare(b.registry));
  }
}

function response(body: string): Response {
  return {
    ok: true,
    status: 200,
    text: async () => body
  } as Response;
}

function normalizePackageName(packageName: string): string {
  return packageName.trim().toLowerCase().replace(/_/g, "-");
}

function mergeSyncMetadata(
  existing: PackageIndexSyncMetadata | undefined,
  incoming: PackageIndexSyncMetadata | undefined
): PackageIndexSyncMetadata | undefined {
  if (incoming?.sourceUrl && existing?.sourceUrl && incoming.sourceUrl !== existing.sourceUrl) {
    return incoming;
  }
  const merged = { ...existing, ...incoming };
  return Object.keys(merged).length > 0 ? merged : undefined;
}

import assert from "node:assert/strict";
import test from "node:test";
import { cloneDefaultConfig } from "../src/config";
import type { PackageCacheStore } from "../src/package/cache";
import {
  CARGO_LIGHTWEIGHT_PACKAGE_LIMIT,
  LIGHTWEIGHT_PACKAGE_LIMIT,
  configuredPackageSyncLimit,
  selectConfiguredPackageSyncRegistries,
  shouldSyncPackageIndex,
  syncConfiguredPackageIndexes
} from "../src/package/configSync";
import type { PackageIndexStore, PackageStorage } from "../src/package/storage";
import type { PackageIndexEntry, PackageRegistry, PackageResolution, VibeGuardConfig } from "../src/types";

test("syncs missing configured package indexes and skips fresh indexes", async () => {
  const now = 1_700_000_000_000;
  const index = new MemoryPackageIndex(now);
  index.seed("npm", ["react"], "partial", now - 60_000);
  const fetchedUrls: string[] = [];
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
    }
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

test("selects detected package registries while respecting configured languages", () => {
  assert.deepEqual(selectConfiguredPackageSyncRegistries(["npm", "pypi"], ["npm", "maven"]), ["npm"]);
  assert.deepEqual(selectConfiguredPackageSyncRegistries(["pypi"], ["npm"]), ["pypi"]);
  assert.deepEqual(selectConfiguredPackageSyncRegistries(["npm", "npm", "maven"], []), ["npm", "maven"]);
  assert.deepEqual(selectConfiguredPackageSyncRegistries([], ["npm"]), []);
});

function testConfig(packageCache: VibeGuardConfig["package_cache"]): VibeGuardConfig {
  return {
    ...cloneDefaultConfig(),
    package_cache: packageCache
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
    { coverage: "partial" | "full"; updatedAt: number; packages: Set<string> }
  >();

  constructor(private readonly now: number) {}

  seed(registry: PackageRegistry, packageNames: string[], coverage: "partial" | "full", updatedAt: number): void {
    this.entries.set(registry, {
      coverage,
      updatedAt,
      packages: new Set(packageNames.map(normalizePackageName))
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
    coverage: "partial" | "full" = "partial"
  ): Promise<PackageIndexEntry> {
    const existing = this.entries.get(registry);
    const packages = coverage === "full" ? new Set<string>() : new Set(existing?.packages ?? []);
    for (const packageName of packageNames) {
      packages.add(normalizePackageName(packageName));
    }
    this.entries.set(registry, {
      coverage,
      updatedAt: this.now,
      packages
    });
    return {
      registry,
      coverage,
      updatedAt: this.now,
      packageCount: packages.size
    };
  }

  async stats(): Promise<PackageIndexEntry[]> {
    return [...this.entries.entries()]
      .map(([registry, entry]) => ({
        registry,
        coverage: entry.coverage,
        updatedAt: entry.updatedAt,
        packageCount: entry.packages.size
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

import fs from "fs/promises";
import path from "path";
import os from "os";
import { gzip, gunzip } from "zlib";
import { promisify } from "util";
import type {
  PackageIndexEntry,
  PackageIndexSyncMetadata,
  PackageNameIndexLike,
  PackageRegistry,
  PackageResolution
} from "../types";
import { suggestPackageNames } from "./suggestions";

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

export interface PackageCacheStore {
  get(registry: PackageRegistry, packageName: string): Promise<PackageResolution | undefined>;
  set(resolution: PackageResolution): Promise<void>;
}

interface IndexRegistryData {
  coverage: "partial" | "full";
  updatedAt: number;
  packages: string[];
  syncMetadata?: PackageIndexSyncMetadata;
}

interface IndexFileData {
  registries?: Partial<Record<PackageRegistry, IndexRegistryData>>;
}

export class MemoryPackageCache implements PackageCacheStore {
  private readonly entries = new Map<string, PackageResolution>();

  async get(registry: PackageRegistry, packageName: string): Promise<PackageResolution | undefined> {
    return this.entries.get(cacheKey(registry, packageName));
  }

  async set(resolution: PackageResolution): Promise<void> {
    this.entries.set(cacheKey(resolution.registry, resolution.packageName), resolution);
  }
}

export class JsonPackageCache implements PackageCacheStore {
  private entries = new Map<string, PackageResolution>();
  private loaded = false;

  constructor(private readonly filePath: string = defaultCachePath()) {}

  async get(registry: PackageRegistry, packageName: string): Promise<PackageResolution | undefined> {
    await this.load();
    return this.entries.get(cacheKey(registry, packageName));
  }

  async set(resolution: PackageResolution): Promise<void> {
    await this.load();
    this.entries.set(cacheKey(resolution.registry, resolution.packageName), resolution);
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify([...this.entries.values()], null, 2), "utf8");
  }

  private async load(): Promise<void> {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as PackageResolution[];
      for (const entry of parsed) {
        if (entry.registry && entry.packageName) {
          this.entries.set(cacheKey(entry.registry, entry.packageName), entry);
        }
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        throw error;
      }
    }
  }
}

export class JsonPackageNameIndex implements PackageNameIndexLike {
  private registries = new Map<
    PackageRegistry,
    { coverage: "partial" | "full"; updatedAt: number; packages: Set<string>; syncMetadata?: PackageIndexSyncMetadata }
  >();
  private loaded = false;

  constructor(private readonly filePath: string = defaultIndexPath()) {}

  async get(registry: PackageRegistry, packageName: string): Promise<boolean | undefined> {
    await this.load();
    const data = this.registries.get(registry);
    if (!data) {
      return undefined;
    }
    if (data.packages.has(normalizePackageName(packageName))) {
      return true;
    }
    return data.coverage === "full" ? false : undefined;
  }

  async coverage(registry: PackageRegistry): Promise<"partial" | "full" | undefined> {
    await this.load();
    return this.registries.get(registry)?.coverage;
  }

  async suggest(registry: PackageRegistry, packageName: string, limit = 3): Promise<string[]> {
    await this.load();
    const data = this.registries.get(registry);
    if (!data) {
      return [];
    }
    return suggestPackageNames(packageName, data.packages, limit);
  }

  async importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial",
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry> {
    await this.load();
    const existing = this.registries.get(registry);
    const packages = coverage === "full" ? new Set<string>() : new Set(existing?.packages ?? []);

    for (const packageName of packageNames) {
      const normalized = normalizePackageName(packageName);
      if (normalized) {
        packages.add(normalized);
      }
    }

    const entry = {
      coverage,
      updatedAt: Date.now(),
      packages,
      syncMetadata: mergeSyncMetadata(existing?.syncMetadata, syncMetadata)
    };
    this.registries.set(registry, entry);
    await this.save();
    return {
      registry,
      coverage,
      updatedAt: entry.updatedAt,
      packageCount: packages.size,
      ...(entry.syncMetadata ? { syncMetadata: entry.syncMetadata } : {})
    };
  }

  async touch(registry: PackageRegistry, syncMetadata?: PackageIndexSyncMetadata): Promise<PackageIndexEntry> {
    await this.load();
    const existing = this.registries.get(registry);
    if (!existing) {
      throw new Error(`Cannot refresh missing ${registry} package index.`);
    }
    const entry = {
      ...existing,
      updatedAt: Date.now(),
      syncMetadata: mergeSyncMetadata(existing.syncMetadata, syncMetadata)
    };
    this.registries.set(registry, entry);
    await this.save();
    return {
      registry,
      coverage: entry.coverage,
      updatedAt: entry.updatedAt,
      packageCount: entry.packages.size,
      ...(entry.syncMetadata ? { syncMetadata: entry.syncMetadata } : {})
    };
  }

  async applyPackageNameChanges(
    registry: PackageRegistry,
    additions: Iterable<string>,
    removals: Iterable<string>,
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry> {
    await this.load();
    const existing = this.registries.get(registry);
    if (!existing) {
      throw new Error(`Cannot apply changes to missing ${registry} package index.`);
    }
    const packages = new Set(existing.packages);
    for (const packageName of additions) {
      const normalized = normalizePackageName(packageName);
      if (normalized) {
        packages.add(normalized);
      }
    }
    for (const packageName of removals) {
      packages.delete(normalizePackageName(packageName));
    }
    const entry = {
      coverage: existing.coverage,
      updatedAt: Date.now(),
      packages,
      syncMetadata: mergeSyncMetadata(existing.syncMetadata, syncMetadata)
    };
    this.registries.set(registry, entry);
    await this.save();
    return {
      registry,
      coverage: entry.coverage,
      updatedAt: entry.updatedAt,
      packageCount: packages.size,
      ...(entry.syncMetadata ? { syncMetadata: entry.syncMetadata } : {})
    };
  }

  async stats(): Promise<PackageIndexEntry[]> {
    await this.load();
    return [...this.registries.entries()]
      .map(([registry, data]) => ({
        registry,
        coverage: data.coverage,
        updatedAt: data.updatedAt,
        packageCount: data.packages.size,
        ...(data.syncMetadata ? { syncMetadata: data.syncMetadata } : {})
      }))
      .sort((a, b) => a.registry.localeCompare(b.registry));
  }

  private async load(): Promise<void> {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    try {
      const raw = await this.readIndexFile();
      const contents = isGzip(raw) ? (await gunzipAsync(raw)).toString("utf8") : raw.toString("utf8");
      const parsed = JSON.parse(contents) as IndexFileData;
      for (const [registry, data] of Object.entries(parsed.registries ?? {})) {
        if (!isRegistry(registry) || !data) {
          continue;
        }
        this.registries.set(registry, {
          coverage: data.coverage === "full" ? "full" : "partial",
          updatedAt: typeof data.updatedAt === "number" ? data.updatedAt : 0,
          packages: new Set((data.packages ?? []).map(normalizePackageName).filter(Boolean)),
          ...(data.syncMetadata ? { syncMetadata: data.syncMetadata } : {})
        });
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        throw error;
      }
    }
  }

  private async save(): Promise<void> {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    const registries: Partial<Record<PackageRegistry, IndexRegistryData>> = {};
    for (const [registry, data] of this.registries.entries()) {
      registries[registry] = {
        coverage: data.coverage,
        updatedAt: data.updatedAt,
        packages: [...data.packages].sort(),
        ...(data.syncMetadata ? { syncMetadata: data.syncMetadata } : {})
      };
    }
    const contents = JSON.stringify({ registries }, null, 2);
    await fs.writeFile(this.filePath, this.filePath.endsWith(".gz") ? await gzipAsync(contents) : contents, "utf8");
  }

  private async readIndexFile(): Promise<Buffer> {
    try {
      return await fs.readFile(this.filePath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const legacyFilePath = this.legacyFilePath();
      if (code !== "ENOENT" || !legacyFilePath) {
        throw error;
      }
      return fs.readFile(legacyFilePath);
    }
  }

  private legacyFilePath(): string | undefined {
    return this.filePath.endsWith(".json.gz") ? this.filePath.slice(0, -3) : undefined;
  }
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

export function defaultCachePath(): string {
  return path.join(os.homedir(), ".vibeguard", "package-cache.json");
}

export function defaultIndexPath(): string {
  return path.join(os.homedir(), ".vibeguard", "package-index.json.gz");
}

function cacheKey(registry: PackageRegistry, packageName: string): string {
  return `${registry}:${normalizePackageName(packageName)}`;
}

function normalizePackageName(packageName: string): string {
  return packageName.trim().toLowerCase().replace(/_/g, "-");
}

function isRegistry(value: string): value is PackageRegistry {
  return ["npm", "pypi", "cargo", "gomod", "maven"].includes(value);
}

function isGzip(value: Buffer): boolean {
  return value.length >= 2 && value[0] === 0x1f && value[1] === 0x8b;
}

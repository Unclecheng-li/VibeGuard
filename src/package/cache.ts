import fs from "fs/promises";
import path from "path";
import os from "os";
import type { PackageIndexEntry, PackageNameIndexLike, PackageRegistry, PackageResolution } from "../types";

export interface PackageCacheStore {
  get(registry: PackageRegistry, packageName: string): Promise<PackageResolution | undefined>;
  set(resolution: PackageResolution): Promise<void>;
}

interface IndexRegistryData {
  coverage: "partial" | "full";
  updatedAt: number;
  packages: string[];
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
  private registries = new Map<PackageRegistry, { coverage: "partial" | "full"; updatedAt: number; packages: Set<string> }>();
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

  async importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial"
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
      packages
    };
    this.registries.set(registry, entry);
    await this.save();
    return {
      registry,
      coverage,
      updatedAt: entry.updatedAt,
      packageCount: packages.size
    };
  }

  async stats(): Promise<PackageIndexEntry[]> {
    await this.load();
    return [...this.registries.entries()]
      .map(([registry, data]) => ({
        registry,
        coverage: data.coverage,
        updatedAt: data.updatedAt,
        packageCount: data.packages.size
      }))
      .sort((a, b) => a.registry.localeCompare(b.registry));
  }

  private async load(): Promise<void> {
    if (this.loaded) {
      return;
    }
    this.loaded = true;
    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as IndexFileData;
      for (const [registry, data] of Object.entries(parsed.registries ?? {})) {
        if (!isRegistry(registry) || !data) {
          continue;
        }
        this.registries.set(registry, {
          coverage: data.coverage === "full" ? "full" : "partial",
          updatedAt: typeof data.updatedAt === "number" ? data.updatedAt : 0,
          packages: new Set((data.packages ?? []).map(normalizePackageName).filter(Boolean))
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
        packages: [...data.packages].sort()
      };
    }
    await fs.writeFile(this.filePath, JSON.stringify({ registries }, null, 2), "utf8");
  }
}

export function defaultCachePath(): string {
  return path.join(os.homedir(), ".vibeguard", "package-cache.json");
}

export function defaultIndexPath(): string {
  return path.join(os.homedir(), ".vibeguard", "package-index.json");
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

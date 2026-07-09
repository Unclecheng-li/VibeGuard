import fs from "fs/promises";
import path from "path";
import os from "os";
import type { PackageRegistry, PackageResolution } from "../types";

export interface PackageCacheStore {
  get(registry: PackageRegistry, packageName: string): Promise<PackageResolution | undefined>;
  set(resolution: PackageResolution): Promise<void>;
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

export function defaultCachePath(): string {
  return path.join(os.homedir(), ".vibeguard", "package-cache.json");
}

function cacheKey(registry: PackageRegistry, packageName: string): string {
  return `${registry}:${packageName.toLowerCase()}`;
}

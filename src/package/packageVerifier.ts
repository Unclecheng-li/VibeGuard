import type { PackageNameIndexLike, PackageReference, PackageResolution, PackageVerifierLike } from "../types";
import { MemoryPackageCache, type PackageCacheStore } from "./cache";
import { seedExists, seedSuggestions } from "./seedCatalog";

export interface PackageVerifierOptions {
  cache?: PackageCacheStore;
  packageIndex?: PackageNameIndexLike;
  timeoutMs?: number;
  ttlMs?: number;
  maxConcurrentRemoteRequests?: number;
  fetchImpl?: typeof fetch;
}

export class PackageVerifier implements PackageVerifierLike {
  private readonly cache: PackageCacheStore;
  private readonly packageIndex?: PackageNameIndexLike;
  private readonly timeoutMs: number;
  private readonly ttlMs: number;
  private readonly maxConcurrentRemoteRequests: number;
  private readonly fetchImpl: typeof fetch;
  private activeRemoteRequests = 0;
  private readonly remoteRequestWaiters: Array<() => void> = [];
  private readonly inFlightRemoteVerifications = new Map<string, Promise<PackageResolution>>();

  constructor(options: PackageVerifierOptions = {}) {
    this.cache = options.cache ?? new MemoryPackageCache();
    this.packageIndex = options.packageIndex;
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.ttlMs = options.ttlMs ?? 24 * 60 * 60 * 1000;
    this.maxConcurrentRemoteRequests = Math.max(1, options.maxConcurrentRemoteRequests ?? 5);
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async verify(reference: PackageReference, mode: "seed" | "remote"): Promise<PackageResolution> {
    const indexed = await this.packageIndex?.get(reference.registry, reference.packageName);
    if (indexed !== undefined) {
      const similarPackages = indexed ? [] : await this.suggestions(reference.registry, reference.packageName);
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists: indexed,
        source: "index",
        lastVerified: Date.now(),
        similarPackages,
        message: indexed ? undefined : "Package was absent from a full local package index."
      };
    }

    const seeded = seedExists(reference.registry, reference.packageName);
    if (seeded !== undefined) {
      const similarPackages = seeded ? [] : await this.suggestions(reference.registry, reference.packageName);
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists: seeded,
        source: "seed",
        lastVerified: Date.now(),
        similarPackages
      };
    }

    const cached = await this.cache.get(reference.registry, reference.packageName);
    if (cached && Date.now() - cached.lastVerified < this.ttlMs) {
      return {
        ...cached,
        source: "cache"
      };
    }

    if (mode !== "remote" || (reference.registry !== "npm" && reference.registry !== "pypi")) {
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists: null,
        source: "unverified",
        lastVerified: Date.now(),
        similarPackages: await this.suggestions(reference.registry, reference.packageName),
        message: "Package was not in the local seed catalog."
      };
    }

    return this.verifyRemoteOnce(reference as PackageReference & { registry: "npm" | "pypi" });
  }

  private async verifyRemoteOnce(reference: PackageReference & { registry: "npm" | "pypi" }): Promise<PackageResolution> {
    const key = remoteVerificationKey(reference);
    const existing = this.inFlightRemoteVerifications.get(key);
    if (existing) {
      return existing;
    }

    const verification = this.verifyAndCacheRemote(reference);
    this.inFlightRemoteVerifications.set(key, verification);
    try {
      return await verification;
    } finally {
      if (this.inFlightRemoteVerifications.get(key) === verification) {
        this.inFlightRemoteVerifications.delete(key);
      }
    }
  }

  private async verifyAndCacheRemote(reference: PackageReference & { registry: "npm" | "pypi" }): Promise<PackageResolution> {
    const resolution = await this.verifyRemote(reference);
    // A transient network failure is not a package-resolution result. Keeping it
    // in the normal TTL cache would suppress verification after connectivity recovers.
    if (resolution.exists !== null) {
      await this.cache.set(resolution);
    }
    return resolution;
  }

  private async verifyRemote(reference: PackageReference & { registry: "npm" | "pypi" }): Promise<PackageResolution> {
    await this.acquireRemoteRequestSlot();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = remoteUrl(reference.registry, reference.packageName);
      const response = await this.fetchImpl(url, {
        method: "GET",
        signal: controller.signal,
        headers: {
          accept: "application/json",
          "user-agent": "VibeGuard/0.1"
        }
      });
      const exists = response.status >= 200 && response.status < 300;
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists,
        source: "remote",
        lastVerified: Date.now(),
        similarPackages: exists ? [] : await this.suggestions(reference.registry, reference.packageName),
        message: exists ? undefined : `Registry returned ${response.status}.`
      };
    } catch (error) {
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists: null,
        source: "unverified",
        lastVerified: Date.now(),
        similarPackages: await this.suggestions(reference.registry, reference.packageName),
        message: error instanceof Error ? error.message : "Remote package verification failed."
      };
    } finally {
      clearTimeout(timeout);
      this.releaseRemoteRequestSlot();
    }
  }

  private async acquireRemoteRequestSlot(): Promise<void> {
    if (this.activeRemoteRequests < this.maxConcurrentRemoteRequests) {
      this.activeRemoteRequests += 1;
      return;
    }
    await new Promise<void>((resolve) => this.remoteRequestWaiters.push(resolve));
  }

  private releaseRemoteRequestSlot(): void {
    const next = this.remoteRequestWaiters.shift();
    if (next) {
      next();
      return;
    }
    this.activeRemoteRequests -= 1;
  }

  private async suggestions(registry: PackageReference["registry"], packageName: string): Promise<string[]> {
    const seed = seedSuggestions(registry, packageName);
    const indexed = (await this.packageIndex?.suggest?.(registry, packageName, 5)) ?? [];
    return [...new Set([...indexed, ...seed])].slice(0, 3);
  }
}

function remoteUrl(registry: "npm" | "pypi", packageName: string): string {
  if (registry === "npm") {
    return `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
  }
  return `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
}

function remoteVerificationKey(reference: PackageReference & { registry: "npm" | "pypi" }): string {
  return `${reference.registry}:${reference.packageName.trim().toLowerCase().replace(/_/g, "-")}`;
}

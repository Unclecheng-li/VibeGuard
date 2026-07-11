import type { PackageNameIndexLike, PackageReference, PackageRegistry, PackageResolution, PackageVerifierLike } from "../types";
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
    const isMavenClassImport = reference.registry === "maven" && reference.mavenLookup === "class";
    const indexed = isMavenClassImport ? undefined : await this.packageIndex?.get(reference.registry, reference.packageName);
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

    const seeded = isMavenClassImport ? undefined : seedExists(reference.registry, reference.packageName);
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

    if (mode !== "remote") {
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

    return this.verifyRemoteOnce(reference);
  }

  private async verifyRemoteOnce(reference: PackageReference): Promise<PackageResolution> {
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

  private async verifyAndCacheRemote(reference: PackageReference): Promise<PackageResolution> {
    const resolution = await this.verifyRemote(reference);
    // A transient network failure is not a package-resolution result. Keeping it
    // in the normal TTL cache would suppress verification after connectivity recovers.
    if (resolution.exists !== null) {
      await this.cache.set(resolution);
    }
    return resolution;
  }

  private async verifyRemote(reference: PackageReference): Promise<PackageResolution> {
    await this.acquireRemoteRequestSlot();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = remoteUrl(reference);
      const response = await this.fetchImpl(url, {
        method: "GET",
        signal: controller.signal,
        headers: {
          accept: "application/json",
          "user-agent": "VibeGuard/0.1"
        }
      });
      const exists = await remoteResponseExists(reference.registry, response);
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists,
        source: exists === null ? "unverified" : "remote",
        lastVerified: Date.now(),
        similarPackages: exists === true ? [] : await this.suggestions(reference.registry, reference.packageName),
        message: remoteVerificationMessage(reference, response.status, exists)
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

function remoteUrl(reference: PackageReference): string {
  switch (reference.registry) {
    case "npm":
      return `https://registry.npmjs.org/${encodeURIComponent(reference.packageName)}`;
    case "pypi":
      return `https://pypi.org/pypi/${encodeURIComponent(reference.packageName)}/json`;
    case "cargo":
      return `https://crates.io/api/v1/crates/${encodeURIComponent(reference.packageName)}`;
    case "gomod":
      return `https://proxy.golang.org/${escapeGoModulePath(reference.packageName)}/@latest`;
    case "maven":
      return mavenSearchUrl(reference);
  }
}

async function remoteResponseExists(registry: PackageRegistry, response: Response): Promise<boolean | null> {
  if (response.status === 404) {
    return false;
  }
  if (!response.ok) {
    return null;
  }
  if (registry !== "maven") {
    return true;
  }

  try {
    const parsed = JSON.parse(await response.text()) as unknown;
    const responseBody = parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>).response : undefined;
    const numFound = responseBody && typeof responseBody === "object" ? (responseBody as Record<string, unknown>).numFound : undefined;
    return typeof numFound === "number" && Number.isFinite(numFound) ? numFound > 0 : null;
  } catch {
    return null;
  }
}

function remoteVerificationMessage(reference: PackageReference, status: number, exists: boolean | null): string | undefined {
  if (exists === true) {
    return undefined;
  }
  if (exists === false) {
    if (reference.registry === "maven") {
      return reference.mavenLookup === "class"
        ? "Maven Central returned no matching imported class."
        : "Maven Central returned no matching coordinate.";
    }
    return `Registry returned ${status}.`;
  }
  return `Registry verification was unavailable (HTTP ${status}).`;
}

function mavenSearchUrl(reference: PackageReference): string {
  const url = new URL("https://search.maven.org/solrsearch/select");
  if (reference.mavenLookup === "class") {
    url.searchParams.set("q", `fc:\"${reference.packageName}\"`);
  } else {
    const separator = reference.packageName.indexOf(":");
    const groupId = separator > 0 ? reference.packageName.slice(0, separator) : "";
    const artifactId = separator > 0 ? reference.packageName.slice(separator + 1) : "";
    if (!groupId || !artifactId || artifactId.includes(":")) {
      throw new Error("Maven package coordinates must use groupId:artifactId format.");
    }
    url.searchParams.set("q", `g:\"${groupId}\" AND a:\"${artifactId}\"`);
  }
  url.searchParams.set("rows", "1");
  url.searchParams.set("wt", "json");
  return url.toString();
}

function escapeGoModulePath(modulePath: string): string {
  return modulePath
    .split("/")
    .map((segment) =>
      [...segment]
        .map((character) => {
          if (character === "!") {
            return "!!";
          }
          if (character >= "A" && character <= "Z") {
            return `!${character.toLowerCase()}`;
          }
          return encodeURIComponent(character);
        })
        .join("")
    )
    .join("/");
}

function remoteVerificationKey(reference: PackageReference): string {
  const normalized =
    reference.registry === "npm" || reference.registry === "pypi" || reference.registry === "cargo"
      ? reference.packageName.trim().toLowerCase().replace(/_/g, "-")
      : reference.packageName.trim();
  return `${reference.registry}:${normalized}`;
}

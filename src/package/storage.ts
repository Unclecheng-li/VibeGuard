import type { PackageIndexEntry, PackageIndexSyncMetadata, PackageNameIndexLike, PackageRegistry } from "../types";
import {
  JsonPackageCache,
  JsonPackageNameIndex,
  defaultCachePath,
  defaultIndexPath,
  type PackageCacheStore
} from "./cache";
import {
  SqlitePackageCache,
  SqlitePackageNameIndex,
  defaultSqlitePath,
  isSqliteAvailable
} from "./sqliteStore";

export type PackageStorageKind = "auto" | "json" | "sqlite";

export interface PackageIndexStore extends PackageNameIndexLike {
  importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage?: "partial" | "full",
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry>;
  applyPackageNameChanges(
    registry: PackageRegistry,
    additions: Iterable<string>,
    removals: Iterable<string>,
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry>;
  touch(registry: PackageRegistry, syncMetadata?: PackageIndexSyncMetadata): Promise<PackageIndexEntry>;
  stats(): Promise<PackageIndexEntry[]>;
}

export interface PackageStorage {
  kind: "json" | "sqlite";
  cache: PackageCacheStore;
  packageIndex: PackageIndexStore;
  cachePath?: string;
  indexPath?: string;
  sqlitePath?: string;
}

export interface PackageStorageOptions {
  kind?: PackageStorageKind;
  cachePath?: string;
  indexPath?: string;
  sqlitePath?: string;
}

export function createPackageStorage(options: PackageStorageOptions = {}): PackageStorage {
  const requested = options.kind ?? "auto";
  if (requested === "sqlite" || (requested === "auto" && isSqliteAvailable())) {
    const sqlitePath = options.sqlitePath ?? defaultSqlitePath();
    return {
      kind: "sqlite",
      cache: new SqlitePackageCache(sqlitePath),
      packageIndex: new SqlitePackageNameIndex(sqlitePath),
      sqlitePath
    };
  }

  const cachePath = options.cachePath ?? defaultCachePath();
  const indexPath = options.indexPath ?? defaultIndexPath();
  return {
    kind: "json",
    cache: new JsonPackageCache(cachePath),
    packageIndex: new JsonPackageNameIndex(indexPath),
    cachePath,
    indexPath
  };
}

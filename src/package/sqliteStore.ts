import { mkdirSync } from "fs";
import { createRequire } from "module";
import os from "os";
import path from "path";
import type {
  PackageIndexEntry,
  PackageIndexSyncMetadata,
  PackageNameIndexLike,
  PackageRegistry,
  PackageResolution
} from "../types";
import type { PackageCacheStore } from "./cache";
import { suggestPackageNames, suggestionSearchTerms } from "./suggestions";

type SqliteModule = typeof import("node:sqlite");

interface DatabaseLike {
  exec(sql: string): void;
  prepare(sql: string): StatementLike;
  close(): void;
}

interface StatementLike {
  get(...parameters: unknown[]): Record<string, unknown> | undefined;
  all(...parameters: unknown[]): Record<string, unknown>[];
  run(...parameters: unknown[]): unknown;
}

export class SqliteUnavailableError extends Error {
  constructor(cause: unknown) {
    super(`SQLite storage is unavailable in this Node runtime: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "SqliteUnavailableError";
  }
}

class SqlitePackageDatabase {
  private readonly database: DatabaseLike;
  private initialized = false;

  constructor(private readonly databasePath: string = defaultSqlitePath()) {
    mkdirSync(path.dirname(databasePath), { recursive: true });
    this.database = createDatabase(databasePath);
  }

  getResolution(registry: PackageRegistry, packageName: string): PackageResolution | undefined {
    this.initialize();
    const row = this.database
      .prepare(
        `SELECT registry, package_name, package_exists, source, last_verified, similar_packages, message
         FROM package_resolution
         WHERE registry = ? AND package_name = ?`
      )
      .get(registry, normalizePackageName(packageName));

    if (!row) {
      return undefined;
    }

    return {
      registry: row.registry as PackageRegistry,
      packageName: row.package_name as string,
      exists: row.package_exists === null || row.package_exists === undefined ? null : Boolean(row.package_exists),
      source: row.source as PackageResolution["source"],
      lastVerified: Number(row.last_verified),
      similarPackages: parseJsonStringArray(row.similar_packages),
      message: typeof row.message === "string" ? row.message : undefined
    };
  }

  setResolution(resolution: PackageResolution): void {
    this.initialize();
    this.database
      .prepare(
        `INSERT INTO package_resolution (
           registry, package_name, package_exists, source, last_verified, similar_packages, message
         ) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(registry, package_name) DO UPDATE SET
           package_exists = excluded.package_exists,
           source = excluded.source,
           last_verified = excluded.last_verified,
           similar_packages = excluded.similar_packages,
           message = excluded.message`
      )
      .run(
        resolution.registry,
        normalizePackageName(resolution.packageName),
        resolution.exists === null ? null : resolution.exists ? 1 : 0,
        resolution.source,
        resolution.lastVerified,
        JSON.stringify(resolution.similarPackages ?? []),
        resolution.message ?? null
      );
  }

  getIndexValue(registry: PackageRegistry, packageName: string): boolean | undefined {
    this.initialize();
    const normalized = normalizePackageName(packageName);
    const packageRow = this.database
      .prepare("SELECT 1 AS found FROM package_index_package WHERE registry = ? AND package_name = ?")
      .get(registry, normalized);
    if (packageRow) {
      return true;
    }
    const coverageRow = this.database.prepare("SELECT coverage FROM package_index_registry WHERE registry = ?").get(registry);
    return coverageRow?.coverage === "full" ? false : undefined;
  }

  coverage(registry: PackageRegistry): "partial" | "full" | undefined {
    this.initialize();
    const row = this.database.prepare("SELECT coverage FROM package_index_registry WHERE registry = ?").get(registry);
    const coverage = row?.coverage;
    return coverage === "full" ? "full" : coverage === "partial" ? "partial" : undefined;
  }

  suggestPackageNames(registry: PackageRegistry, packageName: string, limit = 3): string[] {
    this.initialize();
    const terms = suggestionSearchTerms(packageName).slice(0, 4);
    if (terms.length === 0) {
      return [];
    }

    const where = terms.map(() => "package_name LIKE ? ESCAPE '\\'").join(" OR ");
    const rows = this.database
      .prepare(
        `SELECT package_name
         FROM package_index_package
         WHERE registry = ? AND (${where})
         ORDER BY package_name
         LIMIT 5000`
      )
      .all(registry, ...terms.map((term) => `%${escapeLike(term)}%`));

    return suggestPackageNames(
      packageName,
      rows.map((row) => String(row.package_name ?? "")),
      limit
    );
  }

  importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial",
    syncMetadata?: PackageIndexSyncMetadata
  ): PackageIndexEntry {
    this.initialize();
    const updatedAt = Date.now();

    this.database.exec("BEGIN");
    try {
      if (coverage === "full") {
        this.database.prepare("DELETE FROM package_index_package WHERE registry = ?").run(registry);
      }

      const insertPackage = this.database.prepare(
        `INSERT OR IGNORE INTO package_index_package (registry, package_name)
         VALUES (?, ?)`
      );
      for (const packageName of packageNames) {
        const normalized = normalizePackageName(packageName);
        if (normalized) {
          insertPackage.run(registry, normalized);
        }
      }

      this.database
        .prepare(
          `INSERT INTO package_index_registry (registry, coverage, updated_at, sync_metadata)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(registry) DO UPDATE SET
             coverage = excluded.coverage,
             updated_at = excluded.updated_at,
             sync_metadata = COALESCE(excluded.sync_metadata, package_index_registry.sync_metadata)`
        )
        .run(registry, coverage, updatedAt, serializeSyncMetadata(syncMetadata));
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    const count = this.database
      .prepare("SELECT COUNT(*) AS package_count FROM package_index_package WHERE registry = ?")
      .get(registry);

    return this.indexEntry(registry, coverage, updatedAt, Number(count?.package_count ?? 0));
  }

  touchIndex(registry: PackageRegistry, syncMetadata?: PackageIndexSyncMetadata): PackageIndexEntry {
    this.initialize();
    const existing = this.database
      .prepare("SELECT coverage, sync_metadata FROM package_index_registry WHERE registry = ?")
      .get(registry);
    if (!existing) {
      throw new Error(`Cannot refresh missing ${registry} package index.`);
    }
    const mergedSyncMetadata = mergeSyncMetadata(parseSyncMetadata(existing.sync_metadata), syncMetadata);
    const updatedAt = Date.now();
    this.database
      .prepare(
        `UPDATE package_index_registry
         SET updated_at = ?, sync_metadata = COALESCE(?, sync_metadata)
         WHERE registry = ?`
      )
      .run(updatedAt, serializeSyncMetadata(mergedSyncMetadata), registry);
    const count = this.database
      .prepare("SELECT COUNT(*) AS package_count FROM package_index_package WHERE registry = ?")
      .get(registry);
    return this.indexEntry(
      registry,
      existing.coverage === "full" ? "full" : "partial",
      updatedAt,
      Number(count?.package_count ?? 0),
      mergedSyncMetadata
    );
  }

  applyIndexChanges(
    registry: PackageRegistry,
    additions: Iterable<string>,
    removals: Iterable<string>,
    syncMetadata?: PackageIndexSyncMetadata
  ): PackageIndexEntry {
    this.initialize();
    const existing = this.database
      .prepare("SELECT coverage, sync_metadata FROM package_index_registry WHERE registry = ?")
      .get(registry);
    if (!existing) {
      throw new Error(`Cannot apply changes to missing ${registry} package index.`);
    }

    const coverage = existing.coverage === "full" ? "full" : "partial";
    const mergedSyncMetadata = mergeSyncMetadata(parseSyncMetadata(existing.sync_metadata), syncMetadata);
    const updatedAt = Date.now();
    this.database.exec("BEGIN");
    try {
      const insertPackage = this.database.prepare(
        `INSERT OR IGNORE INTO package_index_package (registry, package_name)
         VALUES (?, ?)`
      );
      for (const packageName of additions) {
        const normalized = normalizePackageName(packageName);
        if (normalized) {
          insertPackage.run(registry, normalized);
        }
      }
      const deletePackage = this.database.prepare(
        "DELETE FROM package_index_package WHERE registry = ? AND package_name = ?"
      );
      for (const packageName of removals) {
        deletePackage.run(registry, normalizePackageName(packageName));
      }
      this.database
        .prepare(
          `UPDATE package_index_registry
           SET updated_at = ?, sync_metadata = COALESCE(?, sync_metadata)
           WHERE registry = ?`
        )
        .run(updatedAt, serializeSyncMetadata(mergedSyncMetadata), registry);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    const count = this.database
      .prepare("SELECT COUNT(*) AS package_count FROM package_index_package WHERE registry = ?")
      .get(registry);
    return this.indexEntry(registry, coverage, updatedAt, Number(count?.package_count ?? 0), mergedSyncMetadata);
  }

  stats(): PackageIndexEntry[] {
    this.initialize();
    const rows = this.database
      .prepare(
        `SELECT r.registry, r.coverage, r.updated_at, r.sync_metadata, COUNT(p.package_name) AS package_count
         FROM package_index_registry r
         LEFT JOIN package_index_package p ON p.registry = r.registry
         GROUP BY r.registry, r.coverage, r.updated_at
         ORDER BY r.registry`
      )
      .all();

    return rows.map((row) =>
      this.indexEntry(
        row.registry as PackageRegistry,
        row.coverage === "full" ? "full" : "partial",
        Number(row.updated_at),
        Number(row.package_count ?? 0),
        parseSyncMetadata(row.sync_metadata)
      )
    );
  }

  close(): void {
    this.database.close();
  }

  private initialize(): void {
    if (this.initialized) {
      return;
    }
    this.initialized = true;
    this.database.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS package_resolution (
        registry TEXT NOT NULL,
        package_name TEXT NOT NULL,
        package_exists INTEGER,
        source TEXT NOT NULL,
        last_verified INTEGER NOT NULL,
        similar_packages TEXT,
        message TEXT,
        PRIMARY KEY (registry, package_name)
      );
      CREATE TABLE IF NOT EXISTS package_index_registry (
        registry TEXT PRIMARY KEY,
        coverage TEXT NOT NULL CHECK (coverage IN ('partial', 'full')),
        updated_at INTEGER NOT NULL,
        sync_metadata TEXT
      );
      CREATE TABLE IF NOT EXISTS package_index_package (
        registry TEXT NOT NULL,
        package_name TEXT NOT NULL,
        PRIMARY KEY (registry, package_name)
      );
      CREATE INDEX IF NOT EXISTS idx_package_index_registry ON package_index_package(registry);
    `);
    const columns = this.database.prepare("PRAGMA table_info(package_index_registry)").all();
    if (!columns.some((column) => column.name === "sync_metadata")) {
      this.database.exec("ALTER TABLE package_index_registry ADD COLUMN sync_metadata TEXT");
    }
  }

  private indexEntry(
    registry: PackageRegistry,
    coverage: "partial" | "full",
    updatedAt: number,
    packageCount: number,
    syncMetadata?: PackageIndexSyncMetadata
  ): PackageIndexEntry {
    return {
      registry,
      coverage,
      updatedAt,
      packageCount,
      ...(syncMetadata ? { syncMetadata } : {})
    };
  }
}

export class SqlitePackageCache implements PackageCacheStore {
  private readonly store: SqlitePackageDatabase;

  constructor(databasePath: string = defaultSqlitePath()) {
    this.store = new SqlitePackageDatabase(databasePath);
  }

  async get(registry: PackageRegistry, packageName: string): Promise<PackageResolution | undefined> {
    return this.store.getResolution(registry, packageName);
  }

  async set(resolution: PackageResolution): Promise<void> {
    this.store.setResolution(resolution);
  }

  close(): void {
    this.store.close();
  }
}

export class SqlitePackageNameIndex implements PackageNameIndexLike {
  private readonly store: SqlitePackageDatabase;

  constructor(databasePath: string = defaultSqlitePath()) {
    this.store = new SqlitePackageDatabase(databasePath);
  }

  async get(registry: PackageRegistry, packageName: string): Promise<boolean | undefined> {
    return this.store.getIndexValue(registry, packageName);
  }

  async coverage(registry: PackageRegistry): Promise<"partial" | "full" | undefined> {
    return this.store.coverage(registry);
  }

  async suggest(registry: PackageRegistry, packageName: string, limit = 3): Promise<string[]> {
    return this.store.suggestPackageNames(registry, packageName, limit);
  }

  async importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial",
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry> {
    return this.store.importPackageNames(registry, packageNames, coverage, syncMetadata);
  }

  async touch(registry: PackageRegistry, syncMetadata?: PackageIndexSyncMetadata): Promise<PackageIndexEntry> {
    return this.store.touchIndex(registry, syncMetadata);
  }

  async applyPackageNameChanges(
    registry: PackageRegistry,
    additions: Iterable<string>,
    removals: Iterable<string>,
    syncMetadata?: PackageIndexSyncMetadata
  ): Promise<PackageIndexEntry> {
    return this.store.applyIndexChanges(registry, additions, removals, syncMetadata);
  }

  async stats(): Promise<PackageIndexEntry[]> {
    return this.store.stats();
  }

  close(): void {
    this.store.close();
  }
}

export function defaultSqlitePath(): string {
  return path.join(os.homedir(), ".vibeguard", "packages.db");
}

export function isSqliteAvailable(): boolean {
  try {
    loadSqlite();
    return true;
  } catch {
    return false;
  }
}

function createDatabase(databasePath: string): DatabaseLike {
  try {
    const sqlite = loadSqlite();
    return new sqlite.DatabaseSync(databasePath, {
      timeout: 5000
    }) as DatabaseLike;
  } catch (error) {
    throw new SqliteUnavailableError(error);
  }
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, (match) => `\\${match}`);
}

function loadSqlite(): SqliteModule {
  const require = createRequire(__filename);
  return require("node:sqlite") as SqliteModule;
}

function normalizePackageName(packageName: string): string {
  return packageName.trim().toLowerCase().replace(/_/g, "-");
}

function serializeSyncMetadata(value: PackageIndexSyncMetadata | undefined): string | null {
  return value && Object.keys(value).length > 0 ? JSON.stringify(value) : null;
}

function parseSyncMetadata(value: unknown): PackageIndexSyncMetadata | undefined {
  if (typeof value !== "string" || !value) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object") {
      return undefined;
    }
    const input = parsed as Record<string, unknown>;
    const metadata: PackageIndexSyncMetadata = {
      ...(typeof input.sourceUrl === "string" ? { sourceUrl: input.sourceUrl } : {}),
      ...(typeof input.etag === "string" ? { etag: input.etag } : {}),
      ...(typeof input.lastModified === "string" ? { lastModified: input.lastModified } : {}),
      ...(typeof input.changeSourceUrl === "string" ? { changeSourceUrl: input.changeSourceUrl } : {}),
      ...(typeof input.changeSequence === "string" ? { changeSequence: input.changeSequence } : {})
    };
    return Object.keys(metadata).length > 0 ? metadata : undefined;
  } catch {
    return undefined;
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

function parseJsonStringArray(value: unknown): string[] | undefined {
  if (typeof value !== "string" || value.length === 0) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is string => typeof item === "string");
    }
  } catch {
    return undefined;
  }
  return undefined;
}

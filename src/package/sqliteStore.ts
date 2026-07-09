import { mkdirSync } from "fs";
import { createRequire } from "module";
import os from "os";
import path from "path";
import type {
  PackageIndexEntry,
  PackageNameIndexLike,
  PackageRegistry,
  PackageResolution
} from "../types";
import type { PackageCacheStore } from "./cache";

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

  importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial"
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
          `INSERT INTO package_index_registry (registry, coverage, updated_at)
           VALUES (?, ?, ?)
           ON CONFLICT(registry) DO UPDATE SET
             coverage = excluded.coverage,
             updated_at = excluded.updated_at`
        )
        .run(registry, coverage, updatedAt);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    const count = this.database
      .prepare("SELECT COUNT(*) AS package_count FROM package_index_package WHERE registry = ?")
      .get(registry);

    return {
      registry,
      coverage,
      updatedAt,
      packageCount: Number(count?.package_count ?? 0)
    };
  }

  stats(): PackageIndexEntry[] {
    this.initialize();
    const rows = this.database
      .prepare(
        `SELECT r.registry, r.coverage, r.updated_at, COUNT(p.package_name) AS package_count
         FROM package_index_registry r
         LEFT JOIN package_index_package p ON p.registry = r.registry
         GROUP BY r.registry, r.coverage, r.updated_at
         ORDER BY r.registry`
      )
      .all();

    return rows.map((row) => ({
      registry: row.registry as PackageRegistry,
      coverage: row.coverage === "full" ? "full" : "partial",
      updatedAt: Number(row.updated_at),
      packageCount: Number(row.package_count ?? 0)
    }));
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
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS package_index_package (
        registry TEXT NOT NULL,
        package_name TEXT NOT NULL,
        PRIMARY KEY (registry, package_name)
      );
      CREATE INDEX IF NOT EXISTS idx_package_index_registry ON package_index_package(registry);
    `);
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

  async importPackageNames(
    registry: PackageRegistry,
    packageNames: Iterable<string>,
    coverage: "partial" | "full" = "partial"
  ): Promise<PackageIndexEntry> {
    return this.store.importPackageNames(registry, packageNames, coverage);
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

function loadSqlite(): SqliteModule {
  const require = createRequire(__filename);
  return require("node:sqlite") as SqliteModule;
}

function normalizePackageName(packageName: string): string {
  return packageName.trim().toLowerCase().replace(/_/g, "-");
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

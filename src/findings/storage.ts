import { mkdirSync } from "fs";
import { createRequire } from "module";
import os from "os";
import path from "path";
import { buildScanReport } from "../reporters";
import type { DetectionLayer, Finding, FindingType, Severity } from "../types";

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

export interface RecordScanRunInput {
  scanId?: string;
  startedAt: number;
  completedAt?: number;
  cwd: string;
  targetPaths: string[];
  fileCount: number;
  findings: Finding[];
}

export interface StoredScanRun {
  scanId: string;
  startedAt: number;
  completedAt: number;
  cwd: string;
  targetPaths: string[];
  fileCount: number;
  findingCount: number;
  activeCount: number;
  dismissedCount: number;
}

export interface StoredFinding extends Finding {
  scanId: string;
  scanCompletedAt: number;
}

export interface FindingQuery {
  limit?: number;
  includeDismissed?: boolean;
}

export interface FindingStoreStats {
  scanCount: number;
  findingCount: number;
  activeCount: number;
  dismissedCount: number;
  latestScanAt?: number;
}

export interface PruneResult {
  deletedScans: number;
  deletedFindings: number;
}

export class SqliteFindingStore {
  private readonly database: DatabaseLike;
  private initialized = false;

  constructor(private readonly databasePath: string = defaultFindingsDbPath()) {
    mkdirSync(path.dirname(databasePath), { recursive: true });
    this.database = createDatabase(databasePath);
  }

  recordScanRun(input: RecordScanRunInput): StoredScanRun {
    this.initialize();
    const completedAt = input.completedAt ?? Date.now();
    const scanId = input.scanId ?? scanRunId(completedAt);
    const report = buildScanReport(input.findings);
    const storedRun: StoredScanRun = {
      scanId,
      startedAt: input.startedAt,
      completedAt,
      cwd: input.cwd,
      targetPaths: [...input.targetPaths],
      fileCount: input.fileCount,
      findingCount: report.count,
      activeCount: report.activeCount,
      dismissedCount: report.dismissedCount
    };

    this.database.exec("BEGIN");
    try {
      this.database
        .prepare(
          `INSERT INTO scan_run (
             scan_id, started_at, completed_at, cwd, target_paths, file_count,
             finding_count, active_count, dismissed_count
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          storedRun.scanId,
          storedRun.startedAt,
          storedRun.completedAt,
          storedRun.cwd,
          JSON.stringify(storedRun.targetPaths),
          storedRun.fileCount,
          storedRun.findingCount,
          storedRun.activeCount,
          storedRun.dismissedCount
        );

      const insertFinding = this.database.prepare(
        `INSERT INTO finding_result (
           scan_id, finding_id, type, severity, message, file_path, line, column,
           end_line, end_column, evidence, suggestion, fix_json, detection_layer,
           detection_rule, timestamp, dismissed, dismissed_reason
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const finding of input.findings) {
        insertFinding.run(
          storedRun.scanId,
          finding.id,
          finding.type,
          finding.severity,
          finding.message,
          finding.file,
          finding.line,
          finding.column,
          finding.endLine ?? null,
          finding.endColumn ?? null,
          finding.evidence,
          finding.suggestion ?? null,
          finding.fix ? JSON.stringify(finding.fix) : null,
          finding.detection_layer,
          finding.detection_rule,
          finding.timestamp,
          finding.dismissed ? 1 : 0,
          finding.dismissed_reason ?? null
        );
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }

    return storedRun;
  }

  listFindings(query: FindingQuery = {}): StoredFinding[] {
    this.initialize();
    const limit = Math.max(1, Math.min(query.limit ?? 50, 1000));
    const rows = this.database
      .prepare(
        `SELECT f.*, s.completed_at AS scan_completed_at
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE (? = 1 OR f.dismissed = 0)
         ORDER BY s.completed_at DESC, f.file_path ASC, f.line ASC, f.column ASC
         LIMIT ?`
      )
      .all(query.includeDismissed ? 1 : 0, limit);
    return rows.map(rowToStoredFinding);
  }

  listScanRuns(limit = 20): StoredScanRun[] {
    this.initialize();
    const boundedLimit = Math.max(1, Math.min(limit, 1000));
    const rows = this.database
      .prepare(
        `SELECT scan_id, started_at, completed_at, cwd, target_paths, file_count,
                finding_count, active_count, dismissed_count
         FROM scan_run
         ORDER BY completed_at DESC
         LIMIT ?`
      )
      .all(boundedLimit);
    return rows.map(rowToStoredScanRun);
  }

  stats(): FindingStoreStats {
    this.initialize();
    const row = this.database
      .prepare(
        `SELECT COUNT(DISTINCT s.scan_id) AS scan_count,
                COUNT(f.finding_id) AS finding_count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count,
                MAX(s.completed_at) AS latest_scan_at
         FROM scan_run s
         LEFT JOIN finding_result f ON f.scan_id = s.scan_id`
      )
      .get();

    return {
      scanCount: Number(row?.scan_count ?? 0),
      findingCount: Number(row?.finding_count ?? 0),
      activeCount: Number(row?.active_count ?? 0),
      dismissedCount: Number(row?.dismissed_count ?? 0),
      latestScanAt: row?.latest_scan_at === null || row?.latest_scan_at === undefined ? undefined : Number(row.latest_scan_at)
    };
  }

  pruneBefore(timestamp: number): PruneResult {
    this.initialize();
    const deletedFindingsRow = this.database
      .prepare(
        `SELECT COUNT(*) AS count
         FROM finding_result
         WHERE scan_id IN (SELECT scan_id FROM scan_run WHERE completed_at < ?)`
      )
      .get(timestamp);
    const deletedScansRow = this.database
      .prepare("SELECT COUNT(*) AS count FROM scan_run WHERE completed_at < ?")
      .get(timestamp);
    this.database
      .prepare("DELETE FROM finding_result WHERE scan_id IN (SELECT scan_id FROM scan_run WHERE completed_at < ?)")
      .run(timestamp);
    this.database.prepare("DELETE FROM scan_run WHERE completed_at < ?").run(timestamp);
    return {
      deletedScans: Number(deletedScansRow?.count ?? 0),
      deletedFindings: Number(deletedFindingsRow?.count ?? 0)
    };
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
      CREATE TABLE IF NOT EXISTS scan_run (
        scan_id TEXT PRIMARY KEY,
        started_at INTEGER NOT NULL,
        completed_at INTEGER NOT NULL,
        cwd TEXT NOT NULL,
        target_paths TEXT NOT NULL,
        file_count INTEGER NOT NULL,
        finding_count INTEGER NOT NULL,
        active_count INTEGER NOT NULL,
        dismissed_count INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS finding_result (
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        message TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line INTEGER NOT NULL,
        column INTEGER NOT NULL,
        end_line INTEGER,
        end_column INTEGER,
        evidence TEXT NOT NULL,
        suggestion TEXT,
        fix_json TEXT,
        detection_layer TEXT NOT NULL,
        detection_rule TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        dismissed INTEGER NOT NULL,
        dismissed_reason TEXT,
        PRIMARY KEY (scan_id, finding_id)
      );
      CREATE INDEX IF NOT EXISTS idx_finding_result_scan ON finding_result(scan_id);
      CREATE INDEX IF NOT EXISTS idx_finding_result_active ON finding_result(dismissed, severity);
      CREATE INDEX IF NOT EXISTS idx_scan_run_completed_at ON scan_run(completed_at);
    `);
  }
}

export function defaultFindingsDbPath(): string {
  return path.join(os.homedir(), ".vibeguard", "findings.db");
}

export function isFindingsStorageAvailable(): boolean {
  try {
    loadSqlite();
    return true;
  } catch {
    return false;
  }
}

function rowToStoredScanRun(row: Record<string, unknown>): StoredScanRun {
  return {
    scanId: row.scan_id as string,
    startedAt: Number(row.started_at),
    completedAt: Number(row.completed_at),
    cwd: row.cwd as string,
    targetPaths: parseJsonStringArray(row.target_paths) ?? [],
    fileCount: Number(row.file_count),
    findingCount: Number(row.finding_count),
    activeCount: Number(row.active_count),
    dismissedCount: Number(row.dismissed_count)
  };
}

function rowToStoredFinding(row: Record<string, unknown>): StoredFinding {
  return {
    scanId: row.scan_id as string,
    scanCompletedAt: Number(row.scan_completed_at),
    id: row.finding_id as string,
    type: row.type as FindingType,
    severity: row.severity as Severity,
    message: row.message as string,
    file: row.file_path as string,
    line: Number(row.line),
    column: Number(row.column),
    endLine: optionalNumber(row.end_line),
    endColumn: optionalNumber(row.end_column),
    evidence: row.evidence as string,
    suggestion: typeof row.suggestion === "string" ? row.suggestion : undefined,
    fix: typeof row.fix_json === "string" ? JSON.parse(row.fix_json) : undefined,
    detection_layer: row.detection_layer as DetectionLayer,
    detection_rule: row.detection_rule as string,
    timestamp: Number(row.timestamp),
    dismissed: Boolean(row.dismissed),
    dismissed_reason: typeof row.dismissed_reason === "string" ? row.dismissed_reason : undefined
  };
}

function optionalNumber(value: unknown): number | undefined {
  return value === null || value === undefined ? undefined : Number(value);
}

function createDatabase(databasePath: string): DatabaseLike {
  const sqlite = loadSqlite();
  return new sqlite.DatabaseSync(databasePath, {
    timeout: 5000
  }) as DatabaseLike;
}

function loadSqlite(): SqliteModule {
  const require = createRequire(__filename);
  return require("node:sqlite") as SqliteModule;
}

function scanRunId(timestamp: number): string {
  return `scan_${timestamp}_${Math.random().toString(36).slice(2, 10)}`;
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

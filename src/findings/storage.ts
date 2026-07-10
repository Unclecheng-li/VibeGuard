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
  /** Stable repository or application identifier for centralized team reporting. */
  project?: string;
  cwd: string;
  targetPaths: string[];
  fileCount: number;
  findings: Finding[];
  findingAuthors?: Record<string, FindingAuthor>;
}

export interface StoredScanRun {
  scanId: string;
  startedAt: number;
  completedAt: number;
  project?: string;
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
  project?: string;
  authorName?: string;
  authorEmail?: string;
}

export interface FindingAuthor {
  name?: string;
  email?: string;
}

export interface FindingQuery {
  limit?: number;
  includeDismissed?: boolean;
  project?: string;
}

export type AuditAuthentication = "oidc" | "token" | "ingest" | "anonymous";
export type AuditOutcome = "success" | "denied";

export interface AuditEventInput {
  timestamp?: number;
  subject?: string;
  role?: "viewer" | "analyst" | "admin" | "none";
  authentication: AuditAuthentication;
  action: string;
  outcome?: AuditOutcome;
  details?: Record<string, string | number | boolean>;
}

export interface StoredAuditEvent extends Required<Pick<AuditEventInput, "authentication" | "action">> {
  id: string;
  timestamp: number;
  subject?: string;
  role?: AuditEventInput["role"];
  outcome: AuditOutcome;
  details: Record<string, string | number | boolean>;
}

export interface AuditEventQuery {
  limit?: number;
  since?: number;
}

export interface FindingStoreStats {
  scanCount: number;
  findingCount: number;
  activeCount: number;
  dismissedCount: number;
  latestScanAt?: number;
}

export interface FindingSummaryBucket {
  key: string;
  count: number;
  activeCount: number;
  dismissedCount: number;
}

export interface FindingRuleSummary extends FindingSummaryBucket {
  type: FindingType;
  severity: Severity;
}

export interface FindingAuthorSummary extends FindingSummaryBucket {
  name?: string;
  email?: string;
  highRiskCount: number;
  highRiskRate: number;
}

export interface FindingTrendPoint {
  date: string;
  scanCount: number;
  findingCount: number;
  activeCount: number;
  dismissedCount: number;
}

export interface FindingProjectSummary {
  key: string;
  scanCount: number;
  findingCount: number;
  activeCount: number;
  dismissedCount: number;
  highRiskCount: number;
  highRiskRate: number;
}

export interface FindingStoreSummary extends FindingStoreStats {
  since?: number;
  project?: string;
  severityCounts: FindingSummaryBucket[];
  typeCounts: FindingSummaryBucket[];
  dismissedReasonCounts: FindingSummaryBucket[];
  authorCounts: FindingAuthorSummary[];
  projectCounts: FindingProjectSummary[];
  topRules: FindingRuleSummary[];
  trend: FindingTrendPoint[];
}

export interface PruneResult {
  deletedScans: number;
  deletedFindings: number;
  deletedAuditEvents: number;
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
      project: normalizeProject(input.project),
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
             scan_id, started_at, completed_at, project, cwd, target_paths, file_count,
             finding_count, active_count, dismissed_count
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          storedRun.scanId,
          storedRun.startedAt,
          storedRun.completedAt,
          storedRun.project ?? null,
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
           detection_rule, timestamp, dismissed, dismissed_reason, author_name, author_email
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const finding of input.findings) {
        const author = input.findingAuthors?.[finding.id];
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
          finding.dismissed_reason ?? null,
          author?.name ?? null,
          author?.email ?? null
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
    const project = normalizeProject(query.project) ?? null;
    const rows = this.database
      .prepare(
        `SELECT f.*, s.completed_at AS scan_completed_at, s.project AS project
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE (? = 1 OR f.dismissed = 0)
           AND (? IS NULL OR s.project = ?)
         ORDER BY s.completed_at DESC, f.file_path ASC, f.line ASC, f.column ASC
         LIMIT ?`
      )
      .all(query.includeDismissed ? 1 : 0, project, project, limit);
    return rows.map(rowToStoredFinding);
  }

  listScanRuns(limit = 20, project?: string): StoredScanRun[] {
    this.initialize();
    const boundedLimit = Math.max(1, Math.min(limit, 1000));
    const rows = this.database
      .prepare(
        `SELECT scan_id, started_at, completed_at, project, cwd, target_paths, file_count,
                finding_count, active_count, dismissed_count
         FROM scan_run
         WHERE (? IS NULL OR project = ?)
         ORDER BY completed_at DESC
         LIMIT ?`
      )
      .all(normalizeProject(project) ?? null, normalizeProject(project) ?? null, boundedLimit);
    return rows.map(rowToStoredScanRun);
  }

  recordAuditEvent(input: AuditEventInput): StoredAuditEvent {
    this.initialize();
    const timestamp = input.timestamp ?? Date.now();
    const event: StoredAuditEvent = {
      id: auditEventId(timestamp),
      timestamp,
      subject: sanitizeAuditText(input.subject, 256),
      role: input.role,
      authentication: input.authentication,
      action: sanitizeAuditText(input.action, 120) ?? "unknown",
      outcome: input.outcome ?? "success",
      details: sanitizeAuditDetails(input.details)
    };
    this.database
      .prepare(
        `INSERT INTO audit_event (event_id, occurred_at, subject, role, authentication, action, outcome, details_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        event.id,
        event.timestamp,
        event.subject ?? null,
        event.role ?? null,
        event.authentication,
        event.action,
        event.outcome,
        JSON.stringify(event.details)
      );
    return event;
  }

  listAuditEvents(query: AuditEventQuery = {}): StoredAuditEvent[] {
    this.initialize();
    const limit = Math.max(1, Math.min(query.limit ?? 100, 1000));
    const rows = this.database
      .prepare(
        `SELECT event_id, occurred_at, subject, role, authentication, action, outcome, details_json
         FROM audit_event
         WHERE (? IS NULL OR occurred_at >= ?)
         ORDER BY occurred_at DESC, event_id DESC
         LIMIT ?`
      )
      .all(query.since ?? null, query.since ?? null, limit);
    return rows.map(rowToStoredAuditEvent);
  }

  stats(project?: string): FindingStoreStats {
    this.initialize();
    const selectedProject = normalizeProject(project) ?? null;
    const row = this.database
      .prepare(
        `SELECT COUNT(DISTINCT s.scan_id) AS scan_count,
                COUNT(f.finding_id) AS finding_count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count,
                MAX(s.completed_at) AS latest_scan_at
         FROM scan_run s
         LEFT JOIN finding_result f ON f.scan_id = s.scan_id
         WHERE (? IS NULL OR s.project = ?)`
      )
      .get(selectedProject, selectedProject);

    return {
      scanCount: Number(row?.scan_count ?? 0),
      findingCount: Number(row?.finding_count ?? 0),
      activeCount: Number(row?.active_count ?? 0),
      dismissedCount: Number(row?.dismissed_count ?? 0),
      latestScanAt: row?.latest_scan_at === null || row?.latest_scan_at === undefined ? undefined : Number(row.latest_scan_at)
    };
  }

  summary(options: { since?: number; topLimit?: number; project?: string } = {}): FindingStoreSummary {
    this.initialize();
    const since = options.since ?? null;
    const project = normalizeProject(options.project) ?? null;
    const topLimit = Math.max(1, Math.min(options.topLimit ?? 10, 100));
    const statsRow = this.database
      .prepare(
        `SELECT COUNT(DISTINCT s.scan_id) AS scan_count,
                COUNT(f.finding_id) AS finding_count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count,
                MAX(s.completed_at) AS latest_scan_at
         FROM scan_run s
         LEFT JOIN finding_result f ON f.scan_id = s.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)`
      )
      .get(since, since, project, project);

    const severityRows = this.database
      .prepare(
        `SELECT f.severity AS key,
                COUNT(*) AS count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY f.severity
         ORDER BY count DESC, f.severity ASC`
      )
      .all(since, since, project, project);

    const typeRows = this.database
      .prepare(
        `SELECT f.type AS key,
                COUNT(*) AS count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY f.type
         ORDER BY count DESC, f.type ASC`
      )
      .all(since, since, project, project);

    const topRuleRows = this.database
      .prepare(
        `SELECT f.detection_rule AS key,
                f.type AS type,
                f.severity AS severity,
                COUNT(*) AS count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY f.detection_rule, f.type, f.severity
         ORDER BY count DESC, active_count DESC, f.detection_rule ASC
         LIMIT ?`
      )
      .all(since, since, project, project, topLimit);

    const dismissedReasonRows = this.database
      .prepare(
        `SELECT COALESCE(NULLIF(TRIM(f.dismissed_reason), ''), 'unspecified') AS key,
                COUNT(*) AS count,
                0 AS active_count,
                COUNT(*) AS dismissed_count
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE f.dismissed = 1 AND (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY key
         ORDER BY count DESC, key ASC`
      )
      .all(since, since, project, project);

    const authorRows = this.database
      .prepare(
        `SELECT COALESCE(NULLIF(LOWER(TRIM(f.author_email)), ''), NULLIF(TRIM(f.author_name), ''), 'unknown') AS key,
                NULLIF(TRIM(f.author_name), '') AS name,
                NULLIF(TRIM(f.author_email), '') AS email,
                COUNT(*) AS count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count,
                SUM(CASE WHEN f.dismissed = 0 AND f.severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_risk_count
         FROM finding_result f
         JOIN scan_run s ON s.scan_id = f.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY key
         ORDER BY high_risk_count DESC, active_count DESC, count DESC, key ASC
         LIMIT ?`
      )
      .all(since, since, project, project, topLimit);

    const projectRows = this.database
      .prepare(
        `SELECT COALESCE(NULLIF(TRIM(s.project), ''), 'Unassigned') AS key,
                COUNT(DISTINCT s.scan_id) AS scan_count,
                COUNT(f.finding_id) AS finding_count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count,
                SUM(CASE WHEN f.dismissed = 0 AND f.severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high_risk_count
         FROM scan_run s
         LEFT JOIN finding_result f ON f.scan_id = s.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY key
         ORDER BY high_risk_count DESC, active_count DESC, finding_count DESC, key ASC
         LIMIT ?`
      )
      .all(since, since, project, project, topLimit);

    const trendRows = this.database
      .prepare(
        `SELECT date(s.completed_at / 1000, 'unixepoch') AS date,
                COUNT(DISTINCT s.scan_id) AS scan_count,
                COUNT(f.finding_id) AS finding_count,
                SUM(CASE WHEN f.dismissed = 0 THEN 1 ELSE 0 END) AS active_count,
                SUM(CASE WHEN f.dismissed = 1 THEN 1 ELSE 0 END) AS dismissed_count
         FROM scan_run s
         LEFT JOIN finding_result f ON f.scan_id = s.scan_id
         WHERE (? IS NULL OR s.completed_at >= ?)
           AND (? IS NULL OR s.project = ?)
         GROUP BY date
         ORDER BY date ASC`
      )
      .all(since, since, project, project);

    return {
      scanCount: Number(statsRow?.scan_count ?? 0),
      findingCount: Number(statsRow?.finding_count ?? 0),
      activeCount: Number(statsRow?.active_count ?? 0),
      dismissedCount: Number(statsRow?.dismissed_count ?? 0),
      latestScanAt:
        statsRow?.latest_scan_at === null || statsRow?.latest_scan_at === undefined ? undefined : Number(statsRow.latest_scan_at),
      since: options.since,
      project: project ?? undefined,
      severityCounts: severityRows.map(rowToSummaryBucket),
      typeCounts: typeRows.map(rowToSummaryBucket),
      dismissedReasonCounts: dismissedReasonRows.map(rowToSummaryBucket),
      authorCounts: authorRows.map(rowToAuthorSummary),
      projectCounts: projectRows.map(rowToProjectSummary),
      topRules: topRuleRows.map(rowToRuleSummary),
      trend: trendRows.map(rowToTrendPoint)
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
    const deletedAuditEventsRow = this.database
      .prepare("SELECT COUNT(*) AS count FROM audit_event WHERE occurred_at < ?")
      .get(timestamp);
    this.database
      .prepare("DELETE FROM finding_result WHERE scan_id IN (SELECT scan_id FROM scan_run WHERE completed_at < ?)")
      .run(timestamp);
    this.database.prepare("DELETE FROM scan_run WHERE completed_at < ?").run(timestamp);
    this.database.prepare("DELETE FROM audit_event WHERE occurred_at < ?").run(timestamp);
    return {
      deletedScans: Number(deletedScansRow?.count ?? 0),
      deletedFindings: Number(deletedFindingsRow?.count ?? 0),
      deletedAuditEvents: Number(deletedAuditEventsRow?.count ?? 0)
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
        project TEXT,
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
        author_name TEXT,
        author_email TEXT,
        PRIMARY KEY (scan_id, finding_id)
      );
      CREATE INDEX IF NOT EXISTS idx_finding_result_scan ON finding_result(scan_id);
      CREATE INDEX IF NOT EXISTS idx_finding_result_active ON finding_result(dismissed, severity);
      CREATE INDEX IF NOT EXISTS idx_scan_run_completed_at ON scan_run(completed_at);
      CREATE TABLE IF NOT EXISTS audit_event (
        event_id TEXT PRIMARY KEY,
        occurred_at INTEGER NOT NULL,
        subject TEXT,
        role TEXT,
        authentication TEXT NOT NULL,
        action TEXT NOT NULL,
        outcome TEXT NOT NULL,
        details_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_event_occurred_at ON audit_event(occurred_at DESC);
    `);
    ensureColumn(this.database, "finding_result", "author_name", "author_name TEXT");
    ensureColumn(this.database, "finding_result", "author_email", "author_email TEXT");
    ensureColumn(this.database, "scan_run", "project", "project TEXT");
    this.database.exec("CREATE INDEX IF NOT EXISTS idx_finding_result_author ON finding_result(author_email, author_name);");
    this.database.exec("CREATE INDEX IF NOT EXISTS idx_scan_run_project_completed_at ON scan_run(project, completed_at);");
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
    project: typeof row.project === "string" ? row.project : undefined,
    cwd: row.cwd as string,
    targetPaths: parseJsonStringArray(row.target_paths) ?? [],
    fileCount: Number(row.file_count),
    findingCount: Number(row.finding_count),
    activeCount: Number(row.active_count),
    dismissedCount: Number(row.dismissed_count)
  };
}

function normalizeProject(value: string | undefined): string | undefined {
  const project = value?.trim();
  if (!project) {
    return undefined;
  }
  if (project.length > 256) {
    throw new Error("Project identifiers must be at most 256 characters.");
  }
  return project;
}

function rowToStoredFinding(row: Record<string, unknown>): StoredFinding {
  return {
    scanId: row.scan_id as string,
    scanCompletedAt: Number(row.scan_completed_at),
    project: typeof row.project === "string" ? row.project : undefined,
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
    dismissed_reason: typeof row.dismissed_reason === "string" ? row.dismissed_reason : undefined,
    authorName: typeof row.author_name === "string" ? row.author_name : undefined,
    authorEmail: typeof row.author_email === "string" ? row.author_email : undefined
  };
}

function rowToSummaryBucket(row: Record<string, unknown>): FindingSummaryBucket {
  return {
    key: String(row.key ?? "unknown"),
    count: Number(row.count ?? 0),
    activeCount: Number(row.active_count ?? 0),
    dismissedCount: Number(row.dismissed_count ?? 0)
  };
}

function rowToRuleSummary(row: Record<string, unknown>): FindingRuleSummary {
  return {
    ...rowToSummaryBucket(row),
    type: row.type as FindingType,
    severity: row.severity as Severity
  };
}

function rowToAuthorSummary(row: Record<string, unknown>): FindingAuthorSummary {
  const bucket = rowToSummaryBucket(row);
  const highRiskCount = Number(row.high_risk_count ?? 0);
  return {
    ...bucket,
    name: typeof row.name === "string" ? row.name : undefined,
    email: typeof row.email === "string" ? row.email : undefined,
    highRiskCount,
    highRiskRate: bucket.activeCount === 0 ? 0 : highRiskCount / bucket.activeCount
  };
}

function rowToProjectSummary(row: Record<string, unknown>): FindingProjectSummary {
  const activeCount = Number(row.active_count ?? 0);
  const highRiskCount = Number(row.high_risk_count ?? 0);
  return {
    key: String(row.key ?? "Unassigned"),
    scanCount: Number(row.scan_count ?? 0),
    findingCount: Number(row.finding_count ?? 0),
    activeCount,
    dismissedCount: Number(row.dismissed_count ?? 0),
    highRiskCount,
    highRiskRate: activeCount === 0 ? 0 : highRiskCount / activeCount
  };
}

function rowToTrendPoint(row: Record<string, unknown>): FindingTrendPoint {
  return {
    date: String(row.date ?? ""),
    scanCount: Number(row.scan_count ?? 0),
    findingCount: Number(row.finding_count ?? 0),
    activeCount: Number(row.active_count ?? 0),
    dismissedCount: Number(row.dismissed_count ?? 0)
  };
}

function rowToStoredAuditEvent(row: Record<string, unknown>): StoredAuditEvent {
  return {
    id: String(row.event_id),
    timestamp: Number(row.occurred_at),
    subject: typeof row.subject === "string" ? row.subject : undefined,
    role: row.role === "viewer" || row.role === "analyst" || row.role === "admin" || row.role === "none" ? row.role : undefined,
    authentication:
      row.authentication === "token" || row.authentication === "ingest" || row.authentication === "anonymous"
        ? row.authentication
        : "oidc",
    action: String(row.action),
    outcome: row.outcome === "denied" ? "denied" : "success",
    details: parseAuditDetails(row.details_json)
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

function ensureColumn(database: DatabaseLike, tableName: string, columnName: string, definition: string): void {
  const rows = database.prepare(`PRAGMA table_info(${tableName})`).all();
  if (rows.some((row) => row.name === columnName)) {
    return;
  }
  database.exec(`ALTER TABLE ${tableName} ADD COLUMN ${definition}`);
}

function loadSqlite(): SqliteModule {
  const require = createRequire(__filename);
  return require("node:sqlite") as SqliteModule;
}

function scanRunId(timestamp: number): string {
  return `scan_${timestamp}_${Math.random().toString(36).slice(2, 10)}`;
}

function auditEventId(timestamp: number): string {
  return `audit_${timestamp}_${Math.random().toString(36).slice(2, 10)}`;
}

function sanitizeAuditDetails(input: AuditEventInput["details"]): Record<string, string | number | boolean> {
  if (!input) {
    return {};
  }
  const details: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(input)) {
    const normalizedKey = key.trim().toLowerCase();
    if (!normalizedKey || normalizedKey.length > 80 || /token|secret|cookie|authorization|password|code|key|credential/.test(normalizedKey)) {
      continue;
    }
    if (typeof value === "string") {
      const normalizedValue = sanitizeAuditText(value, 256);
      if (normalizedValue) {
        details[normalizedKey] = normalizedValue;
      }
    } else if (typeof value === "number" && Number.isFinite(value)) {
      details[normalizedKey] = value;
    } else if (typeof value === "boolean") {
      details[normalizedKey] = value;
    }
    if (Object.keys(details).length >= 16) {
      break;
    }
  }
  return details;
}

function parseAuditDetails(value: unknown): Record<string, string | number | boolean> {
  if (typeof value !== "string") {
    return {};
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? sanitizeAuditDetails(parsed as Record<string, string | number | boolean>)
      : {};
  } catch {
    return {};
  }
}

function sanitizeAuditText(value: string | undefined, maxLength: number): string | undefined {
  const normalized = value?.trim().replace(/[\r\n\u0000]/g, " ").slice(0, maxLength);
  return normalized || undefined;
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

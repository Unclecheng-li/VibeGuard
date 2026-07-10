import type { CodeFix, DetectionLayer, Finding, FindingType, Severity, TextEdit } from "../types";
import type { FindingAuthor, RecordScanRunInput } from "./storage";

export const FINDINGS_INGEST_SCHEMA = "vibeguard.findings.v1";

const findingTypes = new Set<FindingType>([
  "hallucinated_package",
  "hardcoded_secret",
  "insecure_config",
  "ai_pattern_error",
  "sql_injection",
  "xss",
  "ssrf",
  "path_traversal",
  "insecure_deserialization",
  "command_injection",
  "open_redirect",
  "information_leakage",
  "missing_security_measure",
  "other"
]);
const severities = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const detectionLayers = new Set<DetectionLayer>(["L1", "L2", "L3"]);

export interface FindingsIngestPayload {
  schema: typeof FINDINGS_INGEST_SCHEMA;
  scan: RecordScanRunInput;
}

export interface FindingsIngestLimits {
  maxFindings?: number;
  maxTargetPaths?: number;
}

export class FindingsIngestError extends Error {
  constructor(message: string, readonly status = 400) {
    super(message);
    this.name = "FindingsIngestError";
  }
}

export function createFindingsIngestPayload(scan: RecordScanRunInput): FindingsIngestPayload {
  return {
    schema: FINDINGS_INGEST_SCHEMA,
    scan
  };
}

/** Validates network input before it is persisted to the private team database. */
export function parseFindingsIngestPayload(value: unknown, limits: FindingsIngestLimits = {}): RecordScanRunInput {
  const root = object(value, "payload");
  if (root.schema !== FINDINGS_INGEST_SCHEMA) {
    throw new FindingsIngestError(`payload.schema must be ${FINDINGS_INGEST_SCHEMA}.`);
  }
  const scan = object(root.scan, "payload.scan");
  const maxFindings = integerLimit(limits.maxFindings, 10_000, "maxFindings");
  const maxTargetPaths = integerLimit(limits.maxTargetPaths, 1_000, "maxTargetPaths");
  const findings = array(scan.findings, "payload.scan.findings", maxFindings).map((item, index) =>
    parseFinding(item, `payload.scan.findings[${index}]`)
  );
  const targetPaths = array(scan.targetPaths, "payload.scan.targetPaths", maxTargetPaths).map((item, index) =>
    text(item, `payload.scan.targetPaths[${index}]`, 4096)
  );
  const findingAuthors = scan.findingAuthors === undefined
    ? undefined
    : parseFindingAuthors(scan.findingAuthors, "payload.scan.findingAuthors", findings);

  const startedAt = timestamp(scan.startedAt, "payload.scan.startedAt");
  const completedAt = scan.completedAt === undefined ? undefined : timestamp(scan.completedAt, "payload.scan.completedAt");
  if (completedAt !== undefined && completedAt < startedAt) {
    throw new FindingsIngestError("payload.scan.completedAt must not be earlier than payload.scan.startedAt.");
  }

  return {
    scanId: optionalText(scan.scanId, "payload.scan.scanId", 200),
    startedAt,
    completedAt,
    project: optionalText(scan.project, "payload.scan.project", 256),
    cwd: text(scan.cwd, "payload.scan.cwd", 4096),
    targetPaths,
    fileCount: nonNegativeInteger(scan.fileCount, "payload.scan.fileCount", 1_000_000),
    findings,
    findingAuthors
  };
}

function parseFinding(value: unknown, path: string): Finding {
  const finding = object(value, path);
  const fix = finding.fix === undefined ? undefined : parseCodeFix(finding.fix, `${path}.fix`);
  return {
    id: text(finding.id, `${path}.id`, 200),
    type: enumeration(finding.type, `${path}.type`, findingTypes),
    severity: enumeration(finding.severity, `${path}.severity`, severities),
    message: text(finding.message, `${path}.message`, 4096),
    file: text(finding.file, `${path}.file`, 4096),
    line: positiveInteger(finding.line, `${path}.line`, 10_000_000),
    column: positiveInteger(finding.column, `${path}.column`, 10_000_000),
    endLine: finding.endLine === undefined ? undefined : positiveInteger(finding.endLine, `${path}.endLine`, 10_000_000),
    endColumn: finding.endColumn === undefined ? undefined : positiveInteger(finding.endColumn, `${path}.endColumn`, 10_000_000),
    evidence: text(finding.evidence, `${path}.evidence`, 16_384),
    suggestion: optionalText(finding.suggestion, `${path}.suggestion`, 4096),
    fix,
    detection_layer: enumeration(finding.detection_layer, `${path}.detection_layer`, detectionLayers),
    detection_rule: text(finding.detection_rule, `${path}.detection_rule`, 200),
    timestamp: timestamp(finding.timestamp, `${path}.timestamp`),
    dismissed: boolean(finding.dismissed, `${path}.dismissed`),
    dismissed_reason: optionalText(finding.dismissed_reason, `${path}.dismissed_reason`, 4096)
  };
}

function parseCodeFix(value: unknown, path: string): CodeFix {
  const fix = object(value, path);
  return {
    description: text(fix.description, `${path}.description`, 4096),
    edits: array(fix.edits, `${path}.edits`, 100).map((item, index) => parseTextEdit(item, `${path}.edits[${index}]`))
  };
}

function parseTextEdit(value: unknown, path: string): TextEdit {
  const edit = object(value, path);
  return {
    startLine: positiveInteger(edit.startLine, `${path}.startLine`, 10_000_000),
    startColumn: positiveInteger(edit.startColumn, `${path}.startColumn`, 10_000_000),
    endLine: positiveInteger(edit.endLine, `${path}.endLine`, 10_000_000),
    endColumn: positiveInteger(edit.endColumn, `${path}.endColumn`, 10_000_000),
    newText: text(edit.newText, `${path}.newText`, 16_384)
  };
}

function parseFindingAuthors(value: unknown, path: string, findings: Finding[]): Record<string, FindingAuthor> {
  const source = object(value, path);
  const allowedIds = new Set(findings.map((finding) => finding.id));
  const entries = Object.entries(source);
  if (entries.length > findings.length) {
    throw new FindingsIngestError(`${path} cannot contain more entries than findings.`);
  }
  const result: Record<string, FindingAuthor> = {};
  for (const [findingId, author] of entries) {
    if (!allowedIds.has(findingId)) {
      throw new FindingsIngestError(`${path} contains an unknown finding id.`);
    }
    const value = object(author, `${path}.${findingId}`);
    const name = optionalText(value.name, `${path}.${findingId}.name`, 320);
    const email = optionalText(value.email, `${path}.${findingId}.email`, 320);
    if (!name && !email) {
      throw new FindingsIngestError(`${path}.${findingId} must include name or email.`);
    }
    result[findingId] = { name, email };
  }
  return result;
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new FindingsIngestError(`${path} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, path: string, maximum: number): unknown[] {
  if (!Array.isArray(value)) {
    throw new FindingsIngestError(`${path} must be an array.`);
  }
  if (value.length > maximum) {
    throw new FindingsIngestError(`${path} exceeds the allowed item count.`, 413);
  }
  return value;
}

function text(value: unknown, path: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new FindingsIngestError(`${path} must be a non-empty string no longer than ${maximum} characters.`);
  }
  return value;
}

function optionalText(value: unknown, path: string, maximum: number): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return text(value, path, maximum);
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    throw new FindingsIngestError(`${path} must be boolean.`);
  }
  return value;
}

function enumeration<T extends string>(value: unknown, path: string, allowed: Set<T>): T {
  if (typeof value !== "string" || !allowed.has(value as T)) {
    throw new FindingsIngestError(`${path} has an unsupported value.`);
  }
  return value as T;
}

function timestamp(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 8_640_000_000_000_000) {
    throw new FindingsIngestError(`${path} must be a valid timestamp.`);
  }
  return value;
}

function positiveInteger(value: unknown, path: string, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > maximum) {
    throw new FindingsIngestError(`${path} must be a positive integer.`);
  }
  return value as number;
}

function nonNegativeInteger(value: unknown, path: string, maximum: number): number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > maximum) {
    throw new FindingsIngestError(`${path} must be a non-negative integer.`);
  }
  return value as number;
}

function integerLimit(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isInteger(value) || value < 1 || value > fallback) {
    throw new Error(`${name} must be an integer between 1 and ${fallback}.`);
  }
  return value;
}

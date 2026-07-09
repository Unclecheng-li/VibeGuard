import type { DetectionLayer, Finding, FindingType, Severity } from "./types";

export interface Position {
  line: number;
  column: number;
}

export interface FindingInput {
  type: FindingType;
  severity: Severity;
  message: string;
  file: string;
  index: number;
  endIndex?: number;
  text: string;
  evidence: string;
  suggestion?: string;
  detectionLayer: DetectionLayer;
  ruleId: string;
  timestamp: number;
}

export function lineStarts(text: string): number[] {
  const starts = [0];
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) === 10) {
      starts.push(index + 1);
    }
  }
  return starts;
}

export function positionAt(text: string, index: number): Position {
  const starts = lineStarts(text);
  let low = 0;
  let high = starts.length - 1;

  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const lineStart = starts[middle];
    const nextLineStart = starts[middle + 1] ?? Number.POSITIVE_INFINITY;
    if (index < lineStart) {
      high = middle - 1;
    } else if (index >= nextLineStart) {
      low = middle + 1;
    } else {
      return {
        line: middle + 1,
        column: index - lineStart + 1
      };
    }
  }

  return {
    line: starts.length,
    column: Math.max(1, index - starts[starts.length - 1] + 1)
  };
}

export function createFinding(input: FindingInput): Finding {
  const start = positionAt(input.text, input.index);
  const end = positionAt(input.text, input.endIndex ?? input.index + Math.max(1, input.evidence.length));
  const normalizedEvidence = compactEvidence(input.evidence);
  const id = stableId([
    input.file,
    input.ruleId,
    start.line.toString(),
    start.column.toString(),
    normalizedEvidence
  ]);

  return {
    id,
    type: input.type,
    severity: input.severity,
    message: input.message,
    file: input.file,
    line: start.line,
    column: start.column,
    endLine: end.line,
    endColumn: end.column,
    evidence: normalizedEvidence,
    suggestion: input.suggestion,
    detection_layer: input.detectionLayer,
    detection_rule: input.ruleId,
    timestamp: input.timestamp,
    dismissed: false
  };
}

export function stableId(parts: string[]): string {
  let hash = 2166136261;
  const input = parts.join("\u001f");
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `vg_${(hash >>> 0).toString(16).padStart(8, "0")}`;
}

export function compactEvidence(value: string, maxLength = 160): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxLength) {
    return compact;
  }
  return `${compact.slice(0, maxLength - 1)}…`;
}

export function lineTextAt(text: string, index: number): string {
  const start = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  const nextNewline = text.indexOf("\n", index);
  const end = nextNewline === -1 ? text.length : nextNewline;
  return text.slice(start, end);
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }

  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export function redactSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 12) {
    return "[redacted]";
  }
  return `${trimmed.slice(0, 6)}…${trimmed.slice(-4)}`;
}

export function isEnvReference(value: string): boolean {
  return /\b(process\.env|import\.meta\.env|os\.getenv|env\.|System\.getenv)\b/i.test(value);
}

export function uniqueFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.detection_rule}:${finding.file}:${finding.line}:${finding.column}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(finding);
    }
  }
  return unique.sort(compareFindings);
}

export function compareFindings(a: Finding, b: Finding): number {
  const severityRank: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
  };
  return (
    severityRank[a.severity] - severityRank[b.severity] ||
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    a.column - b.column ||
    a.detection_rule.localeCompare(b.detection_rule)
  );
}

export function severityMeetsThreshold(severity: Severity, threshold: Severity | "none"): boolean {
  if (threshold === "none") {
    return false;
  }
  const rank: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0
  };
  return rank[severity] >= rank[threshold];
}

export function extensionOf(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  const last = normalized.split("/").pop() ?? "";
  const dot = last.lastIndexOf(".");
  return dot === -1 ? "" : last.slice(dot + 1).toLowerCase();
}

import type { Finding } from "./types";

const genericSuppressionPattern =
  /\b(?:NOSONAR|nosemgrep|snyk(?::ignore|-ignore|\s+ignore)|codeql\s*\[|lgtm\s*\[)\b/i;
const namedToolPattern = /\b(?:sonar(?:cloud|qube|js)?|snyk|semgrep|codeql)\b/i;

export function dedupWithExistingToolAnnotations(text: string, findings: Finding[]): Finding[] {
  const lines = text.split(/\r?\n/);
  return findings.map((finding) => {
    if (finding.detection_layer !== "L2" || finding.dismissed) {
      return finding;
    }
    const annotation = nearbyExistingToolAnnotation(lines, finding);
    if (!annotation) {
      return finding;
    }
    return {
      ...finding,
      dismissed: true,
      dismissed_reason: `Deduplicated with existing SAST annotation: ${annotation}`
    };
  });
}

function nearbyExistingToolAnnotation(lines: string[], finding: Finding): string | undefined {
  const targetLineIndex = Math.max(0, finding.line - 1);
  const firstLineIndex = Math.max(0, targetLineIndex - 2);
  const lastLineIndex = Math.min(lines.length - 1, targetLineIndex);
  for (let index = firstLineIndex; index <= lastLineIndex; index += 1) {
    const comment = extractComment(lines[index]);
    if (!comment) {
      continue;
    }
    if (genericSuppressionPattern.test(comment)) {
      return summarizeAnnotation(comment);
    }
    if (namedToolPattern.test(comment) && mentionsFinding(comment, finding)) {
      return summarizeAnnotation(comment);
    }
  }
  return undefined;
}

function extractComment(line: string): string | undefined {
  const match = line.match(/(?:\/\/|#|--|\/\*|\*)\s*(.+)$/);
  return match?.[1]?.trim();
}

function mentionsFinding(comment: string, finding: Finding): boolean {
  const normalized = normalize(comment);
  return findingTokens(finding).some((token) => normalized.includes(token));
}

function findingTokens(finding: Finding): string[] {
  const values = [finding.detection_rule, finding.type];
  return [...new Set(values.flatMap((value) => tokenVariants(value)))];
}

function tokenVariants(value: string): string[] {
  const lower = value.toLowerCase();
  return [
    normalize(lower),
    normalize(lower.replace(/_/g, "-")),
    normalize(lower.replace(/_/g, " ")),
    normalize(lower.replace(/^sast_/, "")),
    normalize(lower.replace(/^sast_/, "").replace(/_/g, "-")),
    normalize(lower.replace(/^sast_/, "").replace(/_/g, " "))
  ].filter(Boolean);
}

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

function summarizeAnnotation(comment: string): string {
  const singleLine = comment.replace(/\s+/g, " ").trim();
  return singleLine.length > 120 ? `${singleLine.slice(0, 117)}...` : singleLine;
}

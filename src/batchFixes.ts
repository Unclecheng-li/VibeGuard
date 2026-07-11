import type { Finding, Severity, TextEdit } from "./types";

export interface BatchFixPlan {
  findings: Finding[];
  skipped: Finding[];
  excludedL3: Finding[];
}

export interface ProBatchFixPlan {
  safeFindings: Finding[];
  reviewableL3Findings: Finding[];
  skipped: Finding[];
}

/** Selects non-overlapping, deterministic fixes for a single document. */
export function planSafeBatchFixes(findings: Finding[]): BatchFixPlan {
  const fixable = sortedFixableFindings(findings);
  const selected: Finding[] = [];
  const skipped: Finding[] = [];
  const excludedL3: Finding[] = [];
  const acceptedEdits: TextEdit[] = [];

  for (const finding of fixable) {
    if (finding.detection_layer === "L3") {
      excludedL3.push(finding);
      continue;
    }
    const edits = finding.fix?.edits ?? [];
    if (edits.some((edit) => !isValidEdit(edit) || acceptedEdits.some((accepted) => editsOverlap(edit, accepted)))) {
      skipped.push(finding);
      continue;
    }
    selected.push(finding);
    acceptedEdits.push(...edits);
  }

  return {
    findings: selected.sort(compareFindings),
    skipped,
    excludedL3
  };
}

/**
 * Plans a Pro batch with deterministic fixes first and review-required L3 replacements second.
 * A generated edit never displaces a mechanical fix when their ranges overlap.
 */
export function planProBatchFixes(findings: Finding[]): ProBatchFixPlan {
  const safeFindings: Finding[] = [];
  const reviewableL3Findings: Finding[] = [];
  const skipped: Finding[] = [];
  const acceptedEdits: TextEdit[] = [];

  for (const finding of sortedFixableFindings(findings).filter((item) => item.detection_layer !== "L3")) {
    acceptFinding(finding, safeFindings, skipped, acceptedEdits);
  }
  for (const finding of sortedFixableFindings(findings).filter((item) => item.detection_layer === "L3")) {
    acceptFinding(finding, reviewableL3Findings, skipped, acceptedEdits);
  }

  return {
    safeFindings: safeFindings.sort(compareFindings),
    reviewableL3Findings: reviewableL3Findings.sort(compareFindings),
    skipped
  };
}

function sortedFixableFindings(findings: Finding[]): Finding[] {
  return findings
    .filter((finding) => !finding.dismissed && finding.fix && finding.fix.edits.length > 0)
    .sort((left, right) => severityRank(left.severity) - severityRank(right.severity) || compareFindings(left, right));
}

function acceptFinding(
  finding: Finding,
  selected: Finding[],
  skipped: Finding[],
  acceptedEdits: TextEdit[]
): void {
  const edits = finding.fix?.edits ?? [];
  if (edits.some((edit) => !isValidEdit(edit) || acceptedEdits.some((accepted) => editsOverlap(edit, accepted)))) {
    skipped.push(finding);
    return;
  }
  selected.push(finding);
  acceptedEdits.push(...edits);
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
  }
}

function compareFindings(left: Finding, right: Finding): number {
  return left.line - right.line || left.column - right.column || left.id.localeCompare(right.id);
}

function isValidEdit(edit: TextEdit): boolean {
  return (
    edit.startLine >= 1 &&
    edit.startColumn >= 1 &&
    edit.endLine >= edit.startLine &&
    (edit.endLine > edit.startLine || edit.endColumn >= edit.startColumn)
  );
}

function editsOverlap(left: TextEdit, right: TextEdit): boolean {
  return comparePosition(left.startLine, left.startColumn, right.endLine, right.endColumn) < 0 &&
    comparePosition(right.startLine, right.startColumn, left.endLine, left.endColumn) < 0;
}

function comparePosition(leftLine: number, leftColumn: number, rightLine: number, rightColumn: number): number {
  return leftLine - rightLine || leftColumn - rightColumn;
}

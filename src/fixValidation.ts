import { detectSecrets } from "./rules/secrets";
import type { CodeFix, Finding } from "./types";

/**
 * Secret evidence is intentionally redacted, so validate its regenerated safe fix instead of comparing source text.
 */
export function redactedSecretFixStillMatchesSource(finding: Finding, fix: CodeFix, sourceText: string): boolean {
  if (finding.type !== "hardcoded_secret") {
    return false;
  }
  const current = detectSecrets(sourceText, finding.file, finding.timestamp).find(
    (candidate) =>
      candidate.detection_rule === finding.detection_rule &&
      candidate.line === finding.line &&
      candidate.column === finding.column
  );
  return current?.fix !== undefined && sameCodeFix(current.fix, fix);
}

function sameCodeFix(left: CodeFix, right: CodeFix): boolean {
  if (left.description !== right.description || left.edits.length !== right.edits.length) {
    return false;
  }
  return left.edits.every((edit, index) => {
    const other = right.edits[index];
    return (
      edit.startLine === other?.startLine &&
      edit.startColumn === other.startColumn &&
      edit.endLine === other.endLine &&
      edit.endColumn === other.endColumn &&
      edit.newText === other.newText
    );
  });
}

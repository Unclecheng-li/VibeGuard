import { CodeActionKind, type CodeAction, type Diagnostic, type Range, type TextEdit } from "vscode-languageserver/node";
import type { Finding, TextEdit as VibeGuardTextEdit } from "./types";

export function createCodeActionsForFindings(uri: string, findings: Finding[], diagnostics: Diagnostic[]): CodeAction[] {
  const actions: CodeAction[] = [];
  for (const diagnostic of diagnostics.filter((item) => item.source === "VibeGuard")) {
    const finding = findMatchingFixableFinding(findings, diagnostic);
    if (!finding?.fix) {
      continue;
    }
    actions.push({
      title: `Apply VibeGuard fix: ${finding.fix.description}`,
      kind: CodeActionKind.QuickFix,
      diagnostics: [diagnostic],
      isPreferred: true,
      edit: {
        changes: {
          [uri]: finding.fix.edits.map(toLspTextEdit)
        }
      }
    });
  }
  return actions;
}

function findMatchingFixableFinding(findings: Finding[], diagnostic: Diagnostic): Finding | undefined {
  const diagnosticCode = String(diagnostic.code ?? "");
  return findings.find((finding) => {
    if (finding.dismissed || !finding.fix || finding.detection_rule !== diagnosticCode) {
      return false;
    }
    return rangesOverlap(findingRange(finding), diagnostic.range);
  });
}

function findingRange(finding: Finding): Range {
  return {
    start: {
      line: Math.max(0, finding.line - 1),
      character: Math.max(0, finding.column - 1)
    },
    end: {
      line: Math.max(0, (finding.endLine ?? finding.line) - 1),
      character: Math.max(1, (finding.endColumn ?? finding.column + Math.max(1, finding.evidence.length)) - 1)
    }
  };
}

function toLspTextEdit(edit: VibeGuardTextEdit): TextEdit {
  return {
    range: {
      start: {
        line: Math.max(0, edit.startLine - 1),
        character: Math.max(0, edit.startColumn - 1)
      },
      end: {
        line: Math.max(0, edit.endLine - 1),
        character: Math.max(0, edit.endColumn - 1)
      }
    },
    newText: edit.newText
  };
}

function rangesOverlap(a: Range, b: Range): boolean {
  return comparePositions(a.start, b.end) <= 0 && comparePositions(b.start, a.end) <= 0;
}

function comparePositions(a: Range["start"], b: Range["start"]): number {
  return a.line - b.line || a.character - b.character;
}

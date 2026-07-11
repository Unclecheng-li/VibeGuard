import { CodeActionKind, type CodeAction, type Diagnostic, type Range } from "vscode-languageserver/node";
import type { Finding } from "./types";

export const lspIgnoreFindingCommand = "vibeguard.ignoreFinding";
export const lspApplyFixCommand = "vibeguard.applyFix";
export const lspApplyL3FixCommand = "vibeguard.applyL3Fix";
export type LspIgnoreScope = "line" | "file" | "global" | "package";

export interface LspIgnoreFindingCommandArgument {
  findingId: string;
  scope: LspIgnoreScope;
}

export interface LspApplyL3FixCommandArgument {
  findingId: string;
  uri: string;
}

export interface LspApplyFixCommandArgument extends LspApplyL3FixCommandArgument {
  fixIndex: number;
}

export function createCodeActionsForFindings(uri: string, findings: Finding[], diagnostics: Diagnostic[]): CodeAction[] {
  const actions: CodeAction[] = [];
  for (const diagnostic of diagnostics.filter((item) => item.source === "VibeGuard")) {
    const finding = findMatchingFinding(findings, diagnostic);
    if (!finding) {
      continue;
    }

    for (const [index, fix] of allFixesForFinding(finding).entries()) {
      const action: CodeAction = {
        title: `Apply VibeGuard fix: ${fix.description}`,
        kind: CodeActionKind.QuickFix,
        diagnostics: [diagnostic],
        isPreferred: index === 0 && finding.detection_layer !== "L3"
      };
      action.command = {
        title: action.title,
        command: finding.detection_layer === "L3" ? lspApplyL3FixCommand : lspApplyFixCommand,
        arguments:
          finding.detection_layer === "L3"
            ? [{ findingId: finding.id, uri } satisfies LspApplyL3FixCommandArgument]
            : [{ findingId: finding.id, uri, fixIndex: index } satisfies LspApplyFixCommandArgument]
      };
      actions.push(action);
    }

    actions.push(...ignoreActionsForFinding(finding, diagnostic));
  }
  return actions;
}

function allFixesForFinding(finding: Finding): NonNullable<Finding["fix"]>[] {
  if (!finding.fix) {
    return [];
  }
  // L3 replacements remain deliberately singular and review-required.
  return finding.detection_layer === "L3" ? [finding.fix] : [finding.fix, ...(finding.alternativeFixes ?? [])];
}

function findMatchingFinding(findings: Finding[], diagnostic: Diagnostic): Finding | undefined {
  const diagnosticCode = String(diagnostic.code ?? "");
  return findings.find((finding) => {
    if (finding.dismissed || finding.detection_rule !== diagnosticCode) {
      return false;
    }
    return rangesOverlap(findingRange(finding), diagnostic.range);
  });
}

function ignoreActionsForFinding(finding: Finding, diagnostic: Diagnostic): CodeAction[] {
  const scopes: Array<[LspIgnoreScope, string]> = [
    ["line", "Ignore this VibeGuard finding"],
    ["file", "Ignore this VibeGuard rule in this file"],
    ["global", "Ignore this VibeGuard rule globally"]
  ];
  if (finding.type === "hallucinated_package") {
    scopes.push(["package", `Ignore package ${finding.evidence}`]);
  }
  return scopes.map(([scope, title]) => ({
    title,
    kind: CodeActionKind.QuickFix,
    diagnostics: [diagnostic],
    command: {
      title,
      command: lspIgnoreFindingCommand,
      arguments: [{ findingId: finding.id, scope } satisfies LspIgnoreFindingCommandArgument]
    }
  }));
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

function rangesOverlap(a: Range, b: Range): boolean {
  return comparePositions(a.start, b.end) <= 0 && comparePositions(b.start, a.end) <= 0;
}

function comparePositions(a: Range["start"], b: Range["start"]): number {
  return a.line - b.line || a.character - b.character;
}

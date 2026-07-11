import assert from "node:assert/strict";
import test from "node:test";
import { CodeActionKind, type Diagnostic } from "vscode-languageserver/node";
import {
  createCodeActionsForFindings,
  lspApplyFixCommand,
  lspApplyL3FixCommand,
  lspIgnoreFindingCommand
} from "../src/lspActions";
import type { Finding } from "../src/types";

test("creates LSP quick fixes from VibeGuard finding fixes", () => {
  const uri = "file:///repo/app.ts";
  const diagnostic = diagnosticFor("hardcoded_secret_assignment");
  const actions = createCodeActionsForFindings(uri, [finding()], [diagnostic]);

  const fix = actions.find((action) => action.title.startsWith("Apply VibeGuard fix:"));
  assert.equal(actions.length, 4);
  assert.equal(fix?.kind, CodeActionKind.QuickFix);
  assert.equal(fix?.isPreferred, true);
  assert.equal(fix?.diagnostics?.[0], diagnostic);
  assert.equal(fix?.edit, undefined);
  assert.equal(fix?.command?.command, lspApplyFixCommand);
  assert.deepEqual(fix?.command?.arguments?.[0], { findingId: "finding", uri, fixIndex: 0 });
  assert.deepEqual(
    actions.slice(1).map((action) => action.command?.arguments?.[0]),
    [
      { findingId: "finding", scope: "line" },
      { findingId: "finding", scope: "file" },
      { findingId: "finding", scope: "global" }
    ]
  );
  assert.equal(actions.slice(1).every((action) => action.command?.command === lspIgnoreFindingCommand), true);
});

test("creates ignore actions for non-fixable diagnostics but not unrelated diagnostics", () => {
  const uri = "file:///repo/app.ts";
  const actions = createCodeActionsForFindings(
    uri,
    [finding({ fix: undefined }), finding({ id: "other", detection_rule: "insecure_config_eval" })],
    [diagnosticFor("hardcoded_secret_assignment"), diagnosticFor("ai_pattern_default_password")]
  );

  assert.equal(actions.length, 3);
  assert.equal(actions.every((action) => action.edit === undefined && action.command?.command === lspIgnoreFindingCommand), true);
});

test("routes LLM-generated replacements through a review command", () => {
  const uri = "file:///repo/app.ts";
  const diagnostic = diagnosticFor("hardcoded_secret_assignment");
  const actions = createCodeActionsForFindings(uri, [finding({ detection_layer: "L3" })], [diagnostic]);
  const fix = actions.find((action) => action.title.startsWith("Apply VibeGuard fix:"));

  assert.equal(actions.length, 4);
  assert.equal(fix?.edit, undefined);
  assert.equal(fix?.isPreferred, false);
  assert.equal(fix?.command?.command, lspApplyL3FixCommand);
  assert.deepEqual(fix?.command?.arguments?.[0], { findingId: "finding", uri });
});

test("adds a package-specific ignore action for hallucinated package findings", () => {
  const uri = "file:///repo/app.ts";
  const diagnostic = diagnosticFor("hallucinated_package_npm");
  const actions = createCodeActionsForFindings(
    uri,
    [finding({ type: "hallucinated_package", evidence: "private-utils", detection_rule: "hallucinated_package_npm", fix: undefined })],
    [diagnostic]
  );

  assert.equal(actions.length, 4);
  assert.deepEqual(actions.at(-1)?.command?.arguments?.[0], { findingId: "finding", scope: "package" });
  assert.match(actions.at(-1)?.title ?? "", /Ignore package private-utils/);
});

test("exposes alternative verified package replacements as non-preferred LSP quick fixes", () => {
  const uri = "file:///repo/app.ts";
  const diagnostic = diagnosticFor("hallucinated_package_npm");
  const actions = createCodeActionsForFindings(
    uri,
    [
      finding({
        type: "hallucinated_package",
        evidence: "invented-ui-widget",
        detection_rule: "hallucinated_package_npm",
        fix: {
          description: "Replace with react-window",
          edits: [{ startLine: 1, startColumn: 7, endLine: 1, endColumn: 25, newText: "react-window" }]
        },
        alternativeFixes: [
          {
            description: "Replace with react-virtualized",
            edits: [{ startLine: 1, startColumn: 7, endLine: 1, endColumn: 25, newText: "react-virtualized" }]
          }
        ]
      })
    ],
    [diagnostic]
  );
  const fixes = actions.filter((action) => action.command?.command === lspApplyFixCommand);

  assert.equal(actions.length, 6);
  assert.equal(fixes.length, 2);
  assert.equal(fixes[0]?.isPreferred, true);
  assert.equal(fixes[1]?.isPreferred, false);
  assert.match(fixes[1]?.title ?? "", /react-virtualized/);
  assert.deepEqual(fixes[1]?.command?.arguments?.[0], { findingId: "finding", uri, fixIndex: 1 });
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding",
    type: "hardcoded_secret",
    severity: "critical",
    message: "Sensitive value is hardcoded.",
    file: "/repo/app.ts",
    line: 1,
    column: 7,
    endLine: 1,
    endColumn: 33,
    evidence: "apiKey = abc123",
    suggestion: "Read from environment.",
    fix: {
      description: "Read API_KEY from the environment",
      edits: [
        {
          startLine: 1,
          startColumn: 19,
          endLine: 1,
          endColumn: 33,
          newText: 'process.env.API_KEY ?? ""'
        }
      ]
    },
    detection_layer: "L1",
    detection_rule: "hardcoded_secret_assignment",
    timestamp: 1,
    dismissed: false,
    ...overrides
  };
}

function diagnosticFor(code: string): Diagnostic {
  return {
    range: {
      start: { line: 0, character: 6 },
      end: { line: 0, character: 33 }
    },
    source: "VibeGuard",
    code,
    message: "diagnostic"
  };
}

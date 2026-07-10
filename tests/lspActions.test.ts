import assert from "node:assert/strict";
import test from "node:test";
import { CodeActionKind, type Diagnostic } from "vscode-languageserver/node";
import { createCodeActionsForFindings } from "../src/lspActions";
import type { Finding } from "../src/types";

test("creates LSP quick fixes from VibeGuard finding fixes", () => {
  const uri = "file:///repo/app.ts";
  const diagnostic = diagnosticFor("hardcoded_secret_assignment");
  const actions = createCodeActionsForFindings(uri, [finding()], [diagnostic]);

  assert.equal(actions.length, 1);
  assert.equal(actions[0].kind, CodeActionKind.QuickFix);
  assert.equal(actions[0].isPreferred, true);
  assert.equal(actions[0].diagnostics?.[0], diagnostic);
  assert.deepEqual(actions[0].edit?.changes?.[uri]?.[0], {
    range: {
      start: { line: 0, character: 18 },
      end: { line: 0, character: 32 }
    },
    newText: 'process.env.API_KEY ?? ""'
  });
});

test("does not create LSP quick fixes for non-fixable or unrelated diagnostics", () => {
  const uri = "file:///repo/app.ts";
  const actions = createCodeActionsForFindings(
    uri,
    [finding({ fix: undefined }), finding({ id: "other", detection_rule: "insecure_config_eval" })],
    [diagnosticFor("hardcoded_secret_assignment"), diagnosticFor("ai_pattern_default_password")]
  );

  assert.equal(actions.length, 0);
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

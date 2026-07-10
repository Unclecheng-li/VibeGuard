import assert from "node:assert/strict";
import test from "node:test";
import { planSafeBatchFixes } from "../src/batchFixes";
import type { Finding } from "../src/types";

test("plans non-overlapping mechanical fixes by severity", () => {
  const plan = planSafeBatchFixes([
    finding("low", "low", 1, 4, "safe"),
    finding("critical", "critical", 2, 5, "critical"),
    finding("other", "medium", 6, 9, "other")
  ]);

  assert.deepEqual(plan.findings.map((finding) => finding.id), ["critical", "other"]);
  assert.deepEqual(plan.skipped.map((finding) => finding.id), ["low"]);
  assert.equal(plan.excludedL3.length, 0);
});

test("excludes L3 replacements from batch fixes", () => {
  const plan = planSafeBatchFixes([finding("mechanical", "high", 1, 2, "safe"), finding("llm", "high", 3, 4, "generated", "L3")]);

  assert.deepEqual(plan.findings.map((finding) => finding.id), ["mechanical"]);
  assert.deepEqual(plan.excludedL3.map((finding) => finding.id), ["llm"]);
});

function finding(
  id: string,
  severity: Finding["severity"],
  startColumn: number,
  endColumn: number,
  newText: string,
  layer: Finding["detection_layer"] = "L2"
): Finding {
  return {
    id,
    type: "xss",
    severity,
    message: id,
    file: "view.ts",
    line: 1,
    column: startColumn,
    endLine: 1,
    endColumn,
    evidence: id,
    fix: {
      description: id,
      edits: [
        {
          startLine: 1,
          startColumn,
          endLine: 1,
          endColumn,
          newText
        }
      ]
    },
    detection_layer: layer,
    detection_rule: id,
    timestamp: 1,
    dismissed: false
  };
}

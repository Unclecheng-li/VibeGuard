import assert from "node:assert/strict";
import test from "node:test";
import { mergeFindingsForExecutedLayers } from "../src/layers";
import type { DetectionLayer, Finding } from "../src/types";

test("merges findings by replacing only executed layers", () => {
  const existing = [finding("old-l1", "L1"), finding("old-l2", "L2"), finding("old-l3", "L3")];
  const merged = mergeFindingsForExecutedLayers(existing, [finding("new-l1", "L1")], { l1: true, l2: false, l3: false });

  assert.deepEqual(
    merged.map((item) => item.id).sort(),
    ["new-l1", "old-l2", "old-l3"]
  );
});

test("replaceAll drops findings from layers that did not run", () => {
  const existing = [finding("old-l1", "L1"), finding("old-l2", "L2")];
  const merged = mergeFindingsForExecutedLayers(existing, [finding("new-l1", "L1")], { l1: true }, true);

  assert.deepEqual(merged.map((item) => item.id), ["new-l1"]);
});

test("replaces deferred L3 findings without re-running or clearing L2", () => {
  const existing = [finding("old-l1", "L1"), finding("old-l2", "L2"), finding("old-l3", "L3")];
  const merged = mergeFindingsForExecutedLayers(existing, [finding("new-l3", "L3")], { l3: true });

  assert.deepEqual(
    merged.map((item) => item.id).sort(),
    ["new-l3", "old-l1", "old-l2"]
  );
});

function finding(id: string, layer: DetectionLayer): Finding {
  return {
    id,
    type: "other",
    severity: "medium",
    message: id,
    file: "demo.ts",
    line: id === "new-l1" ? 2 : 1,
    column: 1,
    evidence: id,
    detection_layer: layer,
    detection_rule: id,
    timestamp: 1,
    dismissed: false
  };
}

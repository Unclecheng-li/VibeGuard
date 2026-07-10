import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { SqliteFindingStore, isFindingsStorageAvailable } from "../src/findings/storage";
import type { Finding } from "../src/types";

test("stores scan runs and findings in SQLite", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-findings-"));
  const store = new SqliteFindingStore(path.join(tempDir, "findings.db"));
  const completedAt = 123456;

  const run = store.recordScanRun({
    scanId: "scan_test",
    startedAt: completedAt - 25,
    completedAt,
    cwd: tempDir,
    targetPaths: [path.join(tempDir, "app.ts")],
    fileCount: 1,
    findings: [
      finding({ id: "active", file: path.join(tempDir, "app.ts") }),
      finding({ id: "dismissed", dismissed: true, dismissed_reason: "ignored in tests" })
    ]
  });
  const activeFindings = store.listFindings();
  const allFindings = store.listFindings({ includeDismissed: true });
  const stats = store.stats();
  const runs = store.listScanRuns();

  assert.equal(run.findingCount, 2);
  assert.equal(run.activeCount, 1);
  assert.equal(run.dismissedCount, 1);
  assert.equal(activeFindings.length, 1);
  assert.equal(activeFindings[0].id, "active");
  assert.equal(allFindings.length, 2);
  assert.equal(allFindings.find((item) => item.id === "dismissed")?.dismissed_reason, "ignored in tests");
  assert.equal(stats.scanCount, 1);
  assert.equal(stats.findingCount, 2);
  assert.equal(stats.activeCount, 1);
  assert.equal(stats.dismissedCount, 1);
  assert.equal(stats.latestScanAt, completedAt);
  assert.equal(runs[0].targetPaths.length, 1);
  store.close();
});

test("prunes stored scans and findings before a cutoff", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-findings-prune-"));
  const store = new SqliteFindingStore(path.join(tempDir, "findings.db"));
  store.recordScanRun({
    scanId: "old",
    startedAt: 1,
    completedAt: 10,
    cwd: tempDir,
    targetPaths: ["old.ts"],
    fileCount: 1,
    findings: [finding({ id: "old_finding" })]
  });
  store.recordScanRun({
    scanId: "new",
    startedAt: 90,
    completedAt: 100,
    cwd: tempDir,
    targetPaths: ["new.ts"],
    fileCount: 1,
    findings: [finding({ id: "new_finding" })]
  });

  const result = store.pruneBefore(50);
  const findings = store.listFindings({ includeDismissed: true });
  const stats = store.stats();

  assert.equal(result.deletedScans, 1);
  assert.equal(result.deletedFindings, 1);
  assert.deepEqual(findings.map((item) => item.id), ["new_finding"]);
  assert.equal(stats.scanCount, 1);
  store.close();
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding",
    type: "sql_injection",
    severity: "high",
    message: "SQL query uses template interpolation.",
    file: "app.ts",
    line: 1,
    column: 1,
    endLine: 1,
    endColumn: 20,
    evidence: "SELECT ${id}",
    suggestion: "Use parameterized queries.",
    detection_layer: "L2",
    detection_rule: "sast_sql_template_interpolation",
    timestamp: 1,
    dismissed: false,
    ...overrides
  };
}

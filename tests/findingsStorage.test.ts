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
    ],
    findingAuthors: {
      active: { name: "Ada Lovelace", email: "ada@example.com" },
      dismissed: { name: "Ada Lovelace", email: "ada@example.com" }
    }
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
  assert.equal(allFindings.find((item) => item.id === "active")?.authorName, "Ada Lovelace");
  assert.equal(allFindings.find((item) => item.id === "active")?.authorEmail, "ada@example.com");
  assert.equal(stats.scanCount, 1);
  assert.equal(stats.findingCount, 2);
  assert.equal(stats.activeCount, 1);
  assert.equal(stats.dismissedCount, 1);
  assert.equal(stats.latestScanAt, completedAt);
  assert.equal(runs[0].targetPaths.length, 1);
  store.close();
});

test("summarizes findings history for trend dashboards", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-findings-summary-"));
  const store = new SqliteFindingStore(path.join(tempDir, "findings.db"));
  const dayOne = Date.UTC(2026, 0, 1, 12);
  const dayTwo = Date.UTC(2026, 0, 2, 12);

  store.recordScanRun({
    scanId: "day_one",
    startedAt: dayOne - 100,
    completedAt: dayOne,
    cwd: tempDir,
    targetPaths: ["day-one.ts"],
    fileCount: 1,
    findings: [
      finding({ id: "old_sql", timestamp: dayOne, detection_rule: "sast_sql_template_interpolation" }),
      finding({
        id: "old_secret",
        type: "hardcoded_secret",
        severity: "critical",
        detection_layer: "L1",
        detection_rule: "secret_google_api_key",
        timestamp: dayOne
      })
    ],
    findingAuthors: {
      old_sql: { name: "Ada Lovelace", email: "ada@example.com" },
      old_secret: { name: "Ada Lovelace", email: "ada@example.com" }
    }
  });
  store.recordScanRun({
    scanId: "day_two",
    startedAt: dayTwo - 100,
    completedAt: dayTwo,
    cwd: tempDir,
    targetPaths: ["day-two.ts"],
    fileCount: 1,
    findings: [
      finding({ id: "new_sql", timestamp: dayTwo, detection_rule: "sast_sql_template_interpolation" }),
      finding({
        id: "dismissed_sql",
        timestamp: dayTwo,
        detection_rule: "sast_sql_template_interpolation",
        dismissed: true,
        dismissed_reason: "false_positive: covered elsewhere"
      }),
      finding({
        id: "dismissed_unspecified",
        type: "hardcoded_secret",
        severity: "critical",
        detection_layer: "L1",
        detection_rule: "secret_google_api_key",
        timestamp: dayTwo,
        dismissed: true,
        dismissed_reason: ""
      }),
      finding({
        id: "new_xss",
        type: "xss",
        severity: "medium",
        detection_rule: "sast_inner_html_assignment",
        timestamp: dayTwo
      })
    ],
    findingAuthors: {
      new_sql: { name: "Grace Hopper", email: "grace@example.com" },
      dismissed_sql: { name: "Grace Hopper", email: "grace@example.com" },
      dismissed_unspecified: { name: "Ada Lovelace", email: "ada@example.com" },
      new_xss: { name: "Grace Hopper", email: "grace@example.com" }
    }
  });

  const summary = store.summary({ topLimit: 2 });
  const highSeverity = summary.severityCounts.find((bucket) => bucket.key === "high");
  const sqlType = summary.typeCounts.find((bucket) => bucket.key === "sql_injection");

  assert.equal(summary.scanCount, 2);
  assert.equal(summary.findingCount, 6);
  assert.equal(summary.activeCount, 4);
  assert.equal(summary.dismissedCount, 2);
  assert.equal(summary.latestScanAt, dayTwo);
  assert.equal(highSeverity?.count, 3);
  assert.equal(highSeverity?.activeCount, 2);
  assert.equal(highSeverity?.dismissedCount, 1);
  assert.equal(sqlType?.count, 3);
  assert.deepEqual(
    summary.dismissedReasonCounts.map((bucket) => [bucket.key, bucket.count, bucket.activeCount, bucket.dismissedCount]),
    [
      ["false_positive: covered elsewhere", 1, 0, 1],
      ["unspecified", 1, 0, 1]
    ]
  );
  assert.deepEqual(
    summary.authorCounts.map((bucket) => [
      bucket.name,
      bucket.email,
      bucket.count,
      bucket.activeCount,
      bucket.dismissedCount,
      bucket.highRiskCount,
      bucket.highRiskRate
    ]),
    [
      ["Ada Lovelace", "ada@example.com", 3, 2, 1, 2, 1],
      ["Grace Hopper", "grace@example.com", 3, 2, 1, 1, 0.5]
    ]
  );
  assert.equal(summary.topRules.length, 2);
  assert.equal(summary.topRules[0].key, "sast_sql_template_interpolation");
  assert.equal(summary.topRules[0].count, 3);
  assert.deepEqual(
    summary.trend.map((point) => [point.date, point.scanCount, point.findingCount, point.activeCount, point.dismissedCount]),
    [
      ["2026-01-01", 1, 2, 2, 0],
      ["2026-01-02", 1, 4, 2, 2]
    ]
  );

  const recentSummary = store.summary({ since: dayTwo - 1 });
  assert.equal(recentSummary.scanCount, 1);
  assert.equal(recentSummary.findingCount, 4);
  assert.equal(recentSummary.dismissedReasonCounts.length, 2);
  assert.deepEqual(recentSummary.trend.map((point) => point.date), ["2026-01-02"]);
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

import assert from "node:assert/strict";
import test from "node:test";
import { createComplianceReport, formatComplianceMarkdown } from "../src/findings/compliance";
import type { FindingStoreSummary } from "../src/findings/storage";

test("maps stored findings to cautious SOC 2 and ISO 27001 evidence", () => {
  const report = createComplianceReport(summary(), { generatedAt: Date.UTC(2026, 6, 1) });
  const markdown = formatComplianceMarkdown(report);
  const soc2 = report.frameworks.find((framework) => framework.framework === "soc2");
  const iso = report.frameworks.find((framework) => framework.framework === "iso27001");

  assert.equal(soc2?.controls.find((control) => control.id === "CC7.1")?.status, "attention");
  assert.equal(soc2?.controls.find((control) => control.id === "CC7.1")?.activeFindingCount, 1);
  assert.equal(soc2?.controls.find((control) => control.id === "CC6.1")?.status, "observed");
  assert.equal(iso?.controls.find((control) => control.id === "A.8.8")?.status, "attention");
  assert.match(report.disclaimer, /not a certification/i);
  assert.deepEqual(report.audit.dismissalReasons, [{ reason: "false_positive", count: 1 }]);
  assert.match(markdown, /New active risks in latest scan \| 1/);
  assert.deepEqual(report.audit.topRules, [
    {
      rule: "sast_sql_template_interpolation",
      count: 2,
      activeCount: 1,
      falsePositiveCount: 1,
      falsePositiveRate: 0.5
    }
  ]);
  assert.match(markdown, /sast_sql_template_interpolation \| 2 \| 1 \| 1 \| 50%/);
  assert.equal(
    soc2?.controls.find((control) => control.id === "CC7.2")?.evidence.includes("Resolved active risks in latest scan: 2"),
    true
  );
});

test("identifies a project-scoped compliance report", () => {
  const scoped = { ...summary(), project: "acme/payments-api" };
  const report = createComplianceReport(scoped, { generatedAt: Date.UTC(2026, 6, 1) });

  assert.equal(report.summary.project, "acme/payments-api");
  assert.match(formatComplianceMarkdown(report), /Project scope: acme\/payments-api/);
});

test("marks empty scan history as not assessed and produces a source-free Markdown report", () => {
  const report = createComplianceReport(emptySummary(), { frameworks: ["iso27001"], generatedAt: Date.UTC(2026, 6, 1) });
  const markdown = formatComplianceMarkdown(report);

  assert.deepEqual(report.frameworks.map((framework) => framework.framework), ["iso27001"]);
  assert.equal(report.frameworks[0].controls.every((control) => control.status === "not_assessed"), true);
  assert.match(markdown, /This is technical security evidence/);
  assert.match(markdown, /ISO\/IEC 27001:2022 Evidence/);
  assert.equal(markdown.includes("SELECT * FROM accounts"), false);
});

test("includes dashboard activity only as aggregate action evidence", () => {
  const report = createComplianceReport(summary(), {
    auditEvents: [
      {
        id: "audit_1",
        timestamp: 1,
        subject: "security@example.com",
        role: "analyst",
        authentication: "oidc",
        action: "dashboard.compliance_viewed",
        outcome: "success",
        details: { path: "/api/compliance" }
      },
      {
        id: "audit_2",
        timestamp: 2,
        subject: "security@example.com",
        role: "analyst",
        authentication: "oidc",
        action: "dashboard.compliance_viewed",
        outcome: "success",
        details: {}
      },
      {
        id: "audit_3",
        timestamp: 3,
        subject: "viewer@example.com",
        role: "viewer",
        authentication: "oidc",
        action: "dashboard.access_denied",
        outcome: "denied",
        details: {}
      }
    ]
  });
  const markdown = formatComplianceMarkdown(report);

  assert.deepEqual(report.audit.dashboardActions, [
    { action: "dashboard.compliance_viewed", outcome: "success", count: 2 },
    { action: "dashboard.access_denied", outcome: "denied", count: 1 }
  ]);
  assert.match(markdown, /Dashboard Audit Activity/);
  assert.equal(markdown.includes("security@example.com"), false);
  assert.equal(markdown.includes("/api/compliance"), false);
});

function summary(): FindingStoreSummary {
  return {
    scanCount: 3,
    findingCount: 2,
    activeCount: 1,
    dismissedCount: 1,
    latestScanAt: Date.UTC(2026, 5, 30),
    latestScanDelta: {
      previousScanId: "scan-two",
      currentScanId: "scan-three",
      currentCompletedAt: Date.UTC(2026, 5, 30),
      introducedCount: 1,
      resolvedCount: 2,
      persistentCount: 0
    },
    since: Date.UTC(2026, 5, 1),
    severityCounts: [
      { key: "high", count: 1, activeCount: 1, dismissedCount: 0 },
      { key: "medium", count: 1, activeCount: 0, dismissedCount: 1 }
    ],
    typeCounts: [
      { key: "sql_injection", count: 1, activeCount: 1, dismissedCount: 0 },
      { key: "missing_security_measure", count: 1, activeCount: 0, dismissedCount: 1 }
    ],
    dismissedReasonCounts: [{ key: "false_positive", count: 1, activeCount: 0, dismissedCount: 1 }],
    authorCounts: [],
    projectCounts: [],
    topRules: [
      {
        key: "sast_sql_template_interpolation",
        type: "sql_injection",
        severity: "high",
        count: 2,
        activeCount: 1,
        dismissedCount: 1,
        falsePositiveCount: 1,
        falsePositiveRate: 0.5
      }
    ],
    falsePositiveRules: [],
    trend: [{ date: "2026-06-30", scanCount: 3, findingCount: 2, activeCount: 1, dismissedCount: 1 }]
  };
}

function emptySummary(): FindingStoreSummary {
  return {
    scanCount: 0,
    findingCount: 0,
    activeCount: 0,
    dismissedCount: 0,
    severityCounts: [],
    typeCounts: [],
    dismissedReasonCounts: [],
    authorCounts: [],
    projectCounts: [],
    topRules: [],
    falsePositiveRules: [],
    trend: []
  };
}

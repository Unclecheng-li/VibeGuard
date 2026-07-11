import assert from "node:assert/strict";
import test from "node:test";
import { formatFindingsDashboard } from "../src/findings/dashboard";
import type { FindingStoreSummary } from "../src/findings/storage";

test("formats a standalone findings dashboard with embedded summary data", () => {
  const summary: FindingStoreSummary = {
    scanCount: 2,
    findingCount: 4,
    activeCount: 3,
    dismissedCount: 1,
    latestScanAt: Date.UTC(2026, 0, 2, 12),
    latestScanDelta: {
      previousScanId: "scan-one",
      currentScanId: "scan-two",
      currentCompletedAt: Date.UTC(2026, 0, 2, 12),
      introducedCount: 2,
      resolvedCount: 1,
      persistentCount: 1
    },
    since: Date.UTC(2026, 0, 1),
    severityCounts: [
      { key: "critical", count: 1, activeCount: 1, dismissedCount: 0 },
      { key: "high", count: 2, activeCount: 1, dismissedCount: 1 },
      { key: "medium", count: 1, activeCount: 1, dismissedCount: 0 }
    ],
    typeCounts: [
      { key: "hardcoded_secret", count: 1, activeCount: 1, dismissedCount: 0 },
      { key: "sql_injection", count: 3, activeCount: 2, dismissedCount: 1 }
    ],
    dismissedReasonCounts: [{ key: "false_positive: migration fixture", count: 1, activeCount: 0, dismissedCount: 1 }],
    authorCounts: [
      {
        key: "ada@example.com",
        name: "Ada Lovelace",
        email: "ada@example.com",
        count: 3,
        activeCount: 2,
        dismissedCount: 1,
        highRiskCount: 2,
        highRiskRate: 1
      }
    ],
    projectCounts: [
      {
        key: "acme/payments-api",
        scanCount: 2,
        findingCount: 4,
        activeCount: 3,
        dismissedCount: 1,
        highRiskCount: 2,
        highRiskRate: 2 / 3
      }
    ],
    topRules: [
      {
        key: "sast_sql_template_interpolation",
        type: "sql_injection",
        severity: "high",
        count: 3,
        activeCount: 2,
        dismissedCount: 1,
        falsePositiveCount: 1,
        falsePositiveRate: 1 / 3
      }
    ],
    falsePositiveRules: [
      {
        key: "sast_sql_template_interpolation",
        type: "sql_injection",
        severity: "high",
        count: 3,
        activeCount: 2,
        dismissedCount: 1,
        falsePositiveCount: 1,
        falsePositiveRate: 1 / 3
      }
    ],
    trend: [
      { date: "2026-01-01", scanCount: 1, findingCount: 1, activeCount: 1, dismissedCount: 0 },
      { date: "2026-01-02", scanCount: 1, findingCount: 3, activeCount: 2, dismissedCount: 1 }
    ]
  };

  const html = formatFindingsDashboard(summary, {
    dbPath: "/tmp/findings.db",
    generatedAt: Date.UTC(2026, 0, 3),
    adminUrl: "/projects"
  });
  const dataMatch = html.match(/<script type="application\/json" id="vibeguard-summary">([\s\S]*?)<\/script>/);

  assert.match(html, /VibeGuard Security Dashboard/);
  assert.match(html, /Daily Finding Trend/);
  assert.match(html, /Latest Scan Change/);
  assert.match(html, /Persistent/);
  assert.match(html, /Top Detection Rules/);
  assert.match(html, /Rule Feedback/);
  assert.match(html, /FP Rate/);
  assert.match(html, /Dismissal Reasons/);
  assert.match(html, /Developer Risk/);
  assert.match(html, /Project Risk/);
  assert.match(html, /acme\/payments-api/);
  assert.match(html, /Ada Lovelace/);
  assert.match(html, /false_positive: migration fixture/);
  assert.match(html, /Risk posture/);
  assert.match(html, /Project integrations/);
  assert.match(html, /href="\/projects"/);
  assert.ok(dataMatch);
  assert.deepEqual(JSON.parse(dataMatch[1]), summary);

  const hostedHtml = formatFindingsDashboard(
    {
      ...summary,
      projectCounts: [
        ...summary.projectCounts,
        { key: "Unassigned", scanCount: 1, findingCount: 1, activeCount: 1, dismissedCount: 0, highRiskCount: 0, highRiskRate: 0 }
      ]
    },
    { projectFilterBaseUrl: "/?project=", allProjectsUrl: "/" }
  );
  assert.match(hostedHtml, /href="\/\?project=acme%2Fpayments-api"/);
  assert.match(hostedHtml, /href="\/">All projects/);
  assert.equal(hostedHtml.includes("project=Unassigned"), false);
});

test("escapes dashboard text and embedded JSON safely", () => {
  const summary: FindingStoreSummary = {
    scanCount: 1,
    findingCount: 1,
    activeCount: 1,
    dismissedCount: 0,
    latestScanDelta: {
      previousScanId: "</script><script>alert(1)</script>",
      currentScanId: "scan-two",
      currentCompletedAt: Date.UTC(2026, 0, 2),
      introducedCount: 1,
      resolvedCount: 0,
      persistentCount: 0
    },
    severityCounts: [{ key: "critical", count: 1, activeCount: 1, dismissedCount: 0 }],
    typeCounts: [{ key: "other", count: 1, activeCount: 1, dismissedCount: 0 }],
    dismissedReasonCounts: [],
    authorCounts: [],
    projectCounts: [],
    topRules: [
      {
        key: "</script><script>alert(1)</script>",
        type: "other",
        severity: "critical",
        count: 1,
        activeCount: 1,
        dismissedCount: 0,
        falsePositiveCount: 0,
        falsePositiveRate: 0
      }
    ],
    falsePositiveRules: [],
    trend: [{ date: "2026-01-01", scanCount: 1, findingCount: 1, activeCount: 1, dismissedCount: 0 }]
  };

  const html = formatFindingsDashboard(summary);
  const dataMatch = html.match(/<script type="application\/json" id="vibeguard-summary">([\s\S]*?)<\/script>/);

  assert.equal(html.includes("</script><script>alert(1)</script>"), false);
  assert.match(html, /&lt;\/script&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.ok(dataMatch);
  assert.equal(JSON.parse(dataMatch[1]).topRules[0].key, "</script><script>alert(1)</script>");
  assert.equal(JSON.parse(dataMatch[1]).latestScanDelta.previousScanId, "</script><script>alert(1)</script>");
});

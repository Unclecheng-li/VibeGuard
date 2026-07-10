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
    topRules: [
      {
        key: "sast_sql_template_interpolation",
        type: "sql_injection",
        severity: "high",
        count: 3,
        activeCount: 2,
        dismissedCount: 1
      }
    ],
    trend: [
      { date: "2026-01-01", scanCount: 1, findingCount: 1, activeCount: 1, dismissedCount: 0 },
      { date: "2026-01-02", scanCount: 1, findingCount: 3, activeCount: 2, dismissedCount: 1 }
    ]
  };

  const html = formatFindingsDashboard(summary, {
    dbPath: "/tmp/findings.db",
    generatedAt: Date.UTC(2026, 0, 3)
  });
  const dataMatch = html.match(/<script type="application\/json" id="vibeguard-summary">([\s\S]*?)<\/script>/);

  assert.match(html, /VibeGuard Security Dashboard/);
  assert.match(html, /Daily Finding Trend/);
  assert.match(html, /Top Detection Rules/);
  assert.match(html, /Dismissal Reasons/);
  assert.match(html, /Developer Risk/);
  assert.match(html, /Ada Lovelace/);
  assert.match(html, /false_positive: migration fixture/);
  assert.match(html, /Risk posture/);
  assert.ok(dataMatch);
  assert.deepEqual(JSON.parse(dataMatch[1]), summary);
});

test("escapes dashboard text and embedded JSON safely", () => {
  const summary: FindingStoreSummary = {
    scanCount: 1,
    findingCount: 1,
    activeCount: 1,
    dismissedCount: 0,
    severityCounts: [{ key: "critical", count: 1, activeCount: 1, dismissedCount: 0 }],
    typeCounts: [{ key: "other", count: 1, activeCount: 1, dismissedCount: 0 }],
    dismissedReasonCounts: [],
    authorCounts: [],
    topRules: [
      {
        key: "</script><script>alert(1)</script>",
        type: "other",
        severity: "critical",
        count: 1,
        activeCount: 1,
        dismissedCount: 0
      }
    ],
    trend: [{ date: "2026-01-01", scanCount: 1, findingCount: 1, activeCount: 1, dismissedCount: 0 }]
  };

  const html = formatFindingsDashboard(summary);
  const dataMatch = html.match(/<script type="application\/json" id="vibeguard-summary">([\s\S]*?)<\/script>/);

  assert.equal(html.includes("</script><script>alert(1)</script>"), false);
  assert.match(html, /&lt;\/script&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.ok(dataMatch);
  assert.equal(JSON.parse(dataMatch[1]).topRules[0].key, "</script><script>alert(1)</script>");
});

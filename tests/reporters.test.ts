import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import {
  buildScanReport,
  formatGithubAnnotations,
  formatJsonReport,
  formatMarkdownReport,
  formatSarifReport
} from "../src/reporters";
import type { Finding, ScanPerformance } from "../src/types";

test("formats JSON reports with active and dismissed counts", () => {
  const report = buildScanReport([finding({ id: "active" }), finding({ id: "dismissed", dismissed: true })]);
  const parsed = JSON.parse(formatJsonReport(report)) as {
    count: number;
    activeCount: number;
    dismissedCount: number;
  };

  assert.equal(parsed.count, 2);
  assert.equal(parsed.activeCount, 1);
  assert.equal(parsed.dismissedCount, 1);
});

test("formats performance summaries in JSON and Markdown reports", () => {
  const cwd = process.cwd();
  const perf = performance({
    file: path.join(cwd, "src", "slow.ts"),
    timings: {
      totalMs: 125,
      l1Ms: 75,
      l2Ms: 40,
      l3Ms: 0,
      customRulesMs: 5,
      postProcessingMs: 5
    },
    budgets: [{ layer: "L1", elapsedMs: 75, budgetMs: 50, exceeded: true }],
    budgetExceeded: true
  });
  const report = buildScanReport([finding()], [perf]);
  const parsed = JSON.parse(formatJsonReport(report)) as {
    performance: {
      totalMs: number;
      averageMs: number;
      budgetExceededCount: number;
      budgetExceeded: Array<{ layer: string; file: string }>;
    };
  };
  assert.equal(parsed.performance.totalMs, 125);
  assert.equal(parsed.performance.averageMs, 125);
  assert.equal(parsed.performance.budgetExceededCount, 1);
  assert.equal(parsed.performance.budgetExceeded[0].layer, "L1");

  const markdown = formatMarkdownReport(report, 1, cwd);
  assert.match(markdown, /## Performance/);
  assert.match(markdown, /src\/slow\.ts/);
  assert.match(markdown, /Performance Budget Warnings/);
});

test("formats SARIF for active findings with relative artifact locations", () => {
  const cwd = process.cwd();
  const report = buildScanReport([
    finding({
      file: path.join(cwd, "src", "demo.ts"),
      severity: "high",
      detection_rule: "hardcoded_secret_assignment"
    }),
    finding({
      id: "ignored",
      file: path.join(cwd, "src", "ignored.ts"),
      dismissed: true
    })
  ]);

  const sarif = JSON.parse(formatSarifReport(report, cwd)) as {
    runs: Array<{
      tool: { driver: { rules: Array<{ id: string }> } };
      results: Array<{
        ruleId: string;
        level: string;
        locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
      }>;
    }>;
  };

  assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, "hardcoded_secret_assignment");
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].ruleId, "hardcoded_secret_assignment");
  assert.equal(sarif.runs[0].results[0].level, "error");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/demo.ts");
});

test("formats Markdown reports for PR summaries", () => {
  const cwd = process.cwd();
  const markdown = formatMarkdownReport(
    buildScanReport([
      finding({
        file: path.join(cwd, "src", "demo.ts"),
        severity: "critical",
        message: "Problem | with pipe",
        suggestion: "Use safe\nvalue"
      }),
      finding({
        id: "dismissed",
        file: path.join(cwd, "src", "ignored.ts"),
        dismissed: true
      })
    ]),
    3,
    cwd
  );

  assert.match(markdown, /^# VibeGuard Security Scan/);
  assert.match(markdown, /Scanned \*\*3\*\* file/);
  assert.match(markdown, /\| Critical \| 1 \|/);
  assert.match(markdown, /src\/demo\.ts:3:5/);
  assert.match(markdown, /Problem \\| with pipe<br>Use safe<br>value/);
  assert.doesNotMatch(markdown, /ignored\.ts/);
});

test("formats GitHub annotations and escapes workflow command data", () => {
  const cwd = process.cwd();
  const annotations = formatGithubAnnotations(
    [
      finding({
        file: path.join(cwd, "src", "demo.ts"),
        severity: "medium",
        message: "Problem, with newline\nand percent %",
        suggestion: "Use safe: value"
      }),
      finding({
        id: "ignored",
        file: path.join(cwd, "src", "ignored.ts"),
        dismissed: true
      })
    ],
    cwd
  );

  assert.match(annotations, /^::warning /);
  assert.match(annotations, /file=src\/demo\.ts/);
  assert.match(annotations, /title=VibeGuard medium%3A hardcoded_secret_assignment/);
  assert.match(annotations, /Problem, with newline%0Aand percent %25 Use safe: value/);
  assert.doesNotMatch(annotations, /ignored\.ts/);
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding",
    type: "hardcoded_secret",
    severity: "high",
    message: "Sensitive value is hardcoded.",
    file: path.join(process.cwd(), "src", "demo.ts"),
    line: 3,
    column: 5,
    endLine: 3,
    endColumn: 12,
    evidence: "secret",
    suggestion: "Move it to a secret manager.",
    detection_layer: "L1",
    detection_rule: "hardcoded_secret_assignment",
    timestamp: 1,
    dismissed: false,
    ...overrides
  };
}

function performance(overrides: Partial<ScanPerformance> = {}): ScanPerformance {
  return {
    file: path.join(process.cwd(), "src", "demo.ts"),
    lineCount: 1,
    timings: {
      totalMs: 3,
      l1Ms: 1,
      l2Ms: 1,
      l3Ms: 0,
      customRulesMs: 0,
      postProcessingMs: 1
    },
    budgets: [
      {
        layer: "L1",
        elapsedMs: 1,
        budgetMs: 50,
        exceeded: false
      }
    ],
    budgetExceeded: false,
    ...overrides
  };
}

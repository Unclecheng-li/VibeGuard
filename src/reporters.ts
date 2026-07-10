import path from "path";
import type { Finding, ScanBudgetCheck, ScanPerformance, ScanTimings, Severity } from "./types";

export interface ScanReport {
  findings: Finding[];
  count: number;
  activeCount: number;
  dismissedCount: number;
  performance?: ScanPerformanceSummary;
}

export interface ScanBudgetWarning extends ScanBudgetCheck {
  file: string;
}

export interface ScanPerformanceSummary {
  fileCount: number;
  totalMs: number;
  averageMs: number;
  slowestFile?: {
    file: string;
    elapsedMs: number;
  };
  layerTotals: ScanTimings;
  budgetExceededCount: number;
  budgetExceeded: ScanBudgetWarning[];
}

export function buildScanReport(findings: Finding[], performances: ScanPerformance[] = []): ScanReport {
  const activeCount = findings.filter((finding) => !finding.dismissed).length;
  return {
    findings,
    count: findings.length,
    activeCount,
    dismissedCount: findings.length - activeCount,
    performance: performances.length > 0 ? summarizePerformance(performances) : undefined
  };
}

export function formatJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

export function formatHumanReport(report: ScanReport, fileCount: number): string {
  const lines: string[] = [`VibeGuard scanned ${fileCount} file(s).`];
  appendHumanPerformance(lines, report.performance);
  if (report.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n");
  }

  const active = activeFindings(report.findings);
  const dismissed = dismissedFindings(report.findings);
  lines.push(`${active.length} active finding(s), ${dismissed.length} dismissed.`);
  for (const finding of active) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.file}:${finding.line}:${finding.column} ${finding.message}`);
    lines.push(`  ${finding.detection_rule} (${finding.detection_layer})`);
    if (finding.suggestion) {
      lines.push(`  ${finding.suggestion}`);
    }
  }

  if (dismissed.length > 0) {
    lines.push("");
    lines.push("Dismissed findings:");
    for (const finding of dismissed) {
      lines.push(`[DISMISSED:${finding.severity.toUpperCase()}] ${finding.file}:${finding.line}:${finding.column} ${finding.message}`);
      lines.push(`  ${finding.dismissed_reason ?? "Matched ignore rule"}`);
    }
  }

  return lines.join("\n");
}

export function formatMarkdownReport(report: ScanReport, fileCount: number, cwd = process.cwd()): string {
  const active = activeFindings(report.findings);
  const dismissed = dismissedFindings(report.findings);
  const counts = severityCounts(active);
  const lines: string[] = [
    "# VibeGuard Security Scan",
    "",
    `Scanned **${fileCount}** file(s).`,
    "",
    "| Status | Count |",
    "| --- | ---: |",
    `| Active findings | ${active.length} |`,
    `| Dismissed findings | ${dismissed.length} |`,
    "",
    "| Severity | Active |",
    "| --- | ---: |",
    `| Critical | ${counts.critical} |`,
    `| High | ${counts.high} |`,
    `| Medium | ${counts.medium} |`,
    `| Low | ${counts.low} |`,
    `| Info | ${counts.info} |`
  ];
  appendMarkdownPerformance(lines, report.performance, cwd);

  if (active.length === 0) {
    lines.push("", "No active findings.");
    return lines.join("\n");
  }

  lines.push("", "## Active Findings", "");
  lines.push("| Severity | Rule | Location | Message |");
  lines.push("| --- | --- | --- | --- |");
  for (const finding of active) {
    const location = `${toAnnotationPath(finding.file, cwd)}:${finding.line}:${finding.column}`;
    const message = finding.suggestion ? `${finding.message}<br>${finding.suggestion}` : finding.message;
    lines.push(
      `| ${markdownCell(finding.severity)} | ${markdownCell(finding.detection_rule)} | ${markdownCell(location)} | ${markdownCell(message)} |`
    );
  }

  if (dismissed.length > 0) {
    lines.push("", `_${dismissed.length} dismissed finding(s) were omitted from the active table._`);
  }

  return lines.join("\n");
}

export function formatSarifReport(report: ScanReport, cwd = process.cwd()): string {
  const active = activeFindings(report.findings);
  const rules = new Map<string, Finding>();
  for (const finding of active) {
    if (!rules.has(finding.detection_rule)) {
      rules.set(finding.detection_rule, finding);
    }
  }

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "VibeGuard",
              informationUri: "https://github.com/vibeguard/vibeguard",
              rules: [...rules.values()].map((finding) => ({
                id: finding.detection_rule,
                name: finding.detection_rule,
                shortDescription: {
                  text: finding.message
                },
                fullDescription: {
                  text: finding.suggestion ? `${finding.message} ${finding.suggestion}` : finding.message
                },
                properties: {
                  detectionLayer: finding.detection_layer,
                  findingType: finding.type,
                  severity: finding.severity
                }
              }))
            }
          },
          results: active.map((finding) => ({
            ruleId: finding.detection_rule,
            level: sarifLevel(finding.severity),
            message: {
              text: finding.suggestion ? `${finding.message} ${finding.suggestion}` : finding.message
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: toSarifUri(finding.file, cwd)
                  },
                  region: {
                    startLine: finding.line,
                    startColumn: finding.column,
                    endLine: finding.endLine ?? finding.line,
                    endColumn: finding.endColumn ?? finding.column + Math.max(1, finding.evidence.length)
                  }
                }
              }
            ],
            properties: {
              id: finding.id,
              detectionLayer: finding.detection_layer,
              findingType: finding.type,
              evidence: finding.evidence
            }
          }))
        }
      ]
    },
    null,
    2
  );
}

export function formatGithubAnnotations(findings: Finding[], cwd = process.cwd()): string {
  return activeFindings(findings)
    .map((finding) => {
      const command = githubAnnotationCommand(finding.severity);
      const title = `VibeGuard ${finding.severity}: ${finding.detection_rule}`;
      const message = finding.suggestion ? `${finding.message} ${finding.suggestion}` : finding.message;
      const properties = [
        `file=${escapeGithubProperty(toAnnotationPath(finding.file, cwd))}`,
        `line=${finding.line}`,
        `col=${finding.column}`,
        `endLine=${finding.endLine ?? finding.line}`,
        `endColumn=${finding.endColumn ?? finding.column + Math.max(1, finding.evidence.length)}`,
        `title=${escapeGithubProperty(title)}`
      ].join(",");
      return `::${command} ${properties}::${escapeGithubData(message)}`;
    })
    .join("\n");
}

function activeFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => !finding.dismissed);
}

function dismissedFindings(findings: Finding[]): Finding[] {
  return findings.filter((finding) => finding.dismissed);
}

function severityCounts(findings: Finding[]): Record<Severity, number> {
  return {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length,
    info: findings.filter((finding) => finding.severity === "info").length
  };
}

function summarizePerformance(performances: ScanPerformance[]): ScanPerformanceSummary {
  const layerTotals: ScanTimings = {
    totalMs: 0,
    l1Ms: 0,
    l2Ms: 0,
    l3Ms: 0,
    customRulesMs: 0,
    postProcessingMs: 0
  };
  let slowest: ScanPerformance | undefined;
  const budgetExceeded: ScanBudgetWarning[] = [];

  for (const item of performances) {
    layerTotals.totalMs += item.timings.totalMs;
    layerTotals.l1Ms += item.timings.l1Ms;
    layerTotals.l2Ms += item.timings.l2Ms;
    layerTotals.l3Ms += item.timings.l3Ms;
    layerTotals.customRulesMs += item.timings.customRulesMs;
    layerTotals.postProcessingMs += item.timings.postProcessingMs;
    if (!slowest || item.timings.totalMs > slowest.timings.totalMs) {
      slowest = item;
    }
    for (const check of item.budgets) {
      if (check.exceeded) {
        budgetExceeded.push({ ...check, file: item.file });
      }
    }
  }

  return {
    fileCount: performances.length,
    totalMs: layerTotals.totalMs,
    averageMs: layerTotals.totalMs / Math.max(1, performances.length),
    slowestFile: slowest ? { file: slowest.file, elapsedMs: slowest.timings.totalMs } : undefined,
    layerTotals,
    budgetExceededCount: budgetExceeded.length,
    budgetExceeded
  };
}

function appendHumanPerformance(lines: string[], summary: ScanPerformanceSummary | undefined): void {
  if (!summary) {
    return;
  }
  lines.push(
    `Performance: ${formatDuration(summary.totalMs)} total, ${formatDuration(summary.averageMs)} avg/file.`
  );
  if (summary.slowestFile) {
    lines.push(`Slowest file: ${summary.slowestFile.file} (${formatDuration(summary.slowestFile.elapsedMs)}).`);
  }
  if (summary.budgetExceededCount > 0) {
    lines.push(`Performance budget warnings: ${summary.budgetExceededCount}.`);
    for (const warning of summary.budgetExceeded.slice(0, 3)) {
      lines.push(
        `  ${warning.layer} ${warning.file}: ${formatDuration(warning.elapsedMs)} > ${formatDuration(warning.budgetMs)}`
      );
    }
  }
}

function appendMarkdownPerformance(lines: string[], summary: ScanPerformanceSummary | undefined, cwd: string): void {
  if (!summary) {
    return;
  }
  lines.push(
    "",
    "## Performance",
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    `| Total scan time | ${formatDuration(summary.totalMs)} |`,
    `| Average per file | ${formatDuration(summary.averageMs)} |`,
    `| L1 time | ${formatDuration(summary.layerTotals.l1Ms)} |`,
    `| L2 time | ${formatDuration(summary.layerTotals.l2Ms)} |`,
    `| L3 time | ${formatDuration(summary.layerTotals.l3Ms)} |`
  );
  if (summary.slowestFile) {
    lines.push(`| Slowest file | ${markdownCell(toAnnotationPath(summary.slowestFile.file, cwd))} (${formatDuration(summary.slowestFile.elapsedMs)}) |`);
  }
  if (summary.budgetExceededCount === 0) {
    lines.push(`| Budget warnings | 0 |`);
    return;
  }

  lines.push(`| Budget warnings | ${summary.budgetExceededCount} |`, "", "### Performance Budget Warnings", "");
  lines.push("| Layer | Location | Elapsed | Budget |");
  lines.push("| --- | --- | ---: | ---: |");
  for (const warning of summary.budgetExceeded) {
    lines.push(
      `| ${warning.layer} | ${markdownCell(toAnnotationPath(warning.file, cwd))} | ${formatDuration(warning.elapsedMs)} | ${formatDuration(warning.budgetMs)} |`
    );
  }
}

function formatDuration(value: number): string {
  if (value < 1000) {
    return `${value.toFixed(value < 10 ? 1 : 0)}ms`;
  }
  return `${(value / 1000).toFixed(2)}s`;
}

function markdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, "<br>");
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium" || severity === "low") {
    return "warning";
  }
  return "note";
}

function githubAnnotationCommand(severity: Severity): "error" | "warning" | "notice" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium" || severity === "low") {
    return "warning";
  }
  return "notice";
}

function toSarifUri(filePath: string, cwd: string): string {
  return normalizePath(relativeOrOriginal(filePath, cwd));
}

function toAnnotationPath(filePath: string, cwd: string): string {
  return normalizePath(relativeOrOriginal(filePath, cwd));
}

function relativeOrOriginal(filePath: string, cwd: string): string {
  const absolute = path.resolve(filePath);
  const relative = path.relative(cwd, absolute);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative : filePath;
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function escapeGithubData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeGithubProperty(value: string): string {
  return escapeGithubData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

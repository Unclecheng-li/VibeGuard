import path from "path";
import type { Finding, Severity } from "./types";

export interface ScanReport {
  findings: Finding[];
  count: number;
  activeCount: number;
  dismissedCount: number;
}

export function buildScanReport(findings: Finding[]): ScanReport {
  const activeCount = findings.filter((finding) => !finding.dismissed).length;
  return {
    findings,
    count: findings.length,
    activeCount,
    dismissedCount: findings.length - activeCount
  };
}

export function formatJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

export function formatHumanReport(report: ScanReport, fileCount: number): string {
  const lines: string[] = [`VibeGuard scanned ${fileCount} file(s).`];
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

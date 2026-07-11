import type { FindingType } from "../types";
import type { FindingScanDelta, FindingStoreSummary, StoredAuditEvent } from "./storage";

export type ComplianceFramework = "soc2" | "iso27001";
export type ComplianceControlStatus = "not_assessed" | "observed" | "attention";

export interface ComplianceControlEvidence {
  id: string;
  title: string;
  status: ComplianceControlStatus;
  description: string;
  mappedFindingTypes: FindingType[];
  activeFindingCount: number;
  evidence: string[];
}

export interface ComplianceFrameworkReport {
  framework: ComplianceFramework;
  controls: ComplianceControlEvidence[];
}

export interface ComplianceReport {
  generatedAt: number;
  period: {
    since?: number;
    until: number;
  };
  disclaimer: string;
  summary: {
    project?: string;
    scanCount: number;
    findingCount: number;
    activeCount: number;
    dismissedCount: number;
    latestScanAt?: number;
    latestScanDelta?: FindingScanDelta;
  };
  audit: {
    dismissalReasons: Array<{ reason: string; count: number }>;
    topRules: Array<{ rule: string; count: number; activeCount: number; falsePositiveCount: number; falsePositiveRate: number }>;
    dashboardActions: Array<{ action: string; outcome: "success" | "denied"; count: number }>;
  };
  frameworks: ComplianceFrameworkReport[];
}

export interface ComplianceReportOptions {
  frameworks?: ComplianceFramework[];
  generatedAt?: number;
  auditEvents?: StoredAuditEvent[];
}

interface ControlDefinition {
  id: string;
  title: string;
  description: string;
  mappedFindingTypes: FindingType[];
}

const controls: Record<ComplianceFramework, ControlDefinition[]> = {
  soc2: [
    {
      id: "CC6.1",
      title: "Logical access safeguards",
      description: "Evidence from checks for missing authentication and authorization controls in exposed code paths.",
      mappedFindingTypes: ["missing_security_measure"]
    },
    {
      id: "CC7.1",
      title: "Vulnerability identification",
      description: "Evidence from static detection of security defects and unsafe AI-generated code patterns.",
      mappedFindingTypes: [
        "hallucinated_package",
        "hardcoded_secret",
        "insecure_config",
        "ai_pattern_error",
        "sql_injection",
        "xss",
        "ssrf",
        "path_traversal",
        "insecure_deserialization",
        "command_injection",
        "open_redirect",
        "information_leakage"
      ]
    },
    {
      id: "CC7.2",
      title: "Security event monitoring",
      description: "Evidence from stored scan cadence, historical trends, and documented finding dispositions.",
      mappedFindingTypes: []
    }
  ],
  iso27001: [
    {
      id: "A.8.8",
      title: "Management of technical vulnerabilities",
      description: "Evidence from static detection of known insecure implementation patterns and remediation findings.",
      mappedFindingTypes: [
        "hallucinated_package",
        "hardcoded_secret",
        "insecure_config",
        "ai_pattern_error",
        "sql_injection",
        "xss",
        "ssrf",
        "path_traversal",
        "insecure_deserialization",
        "command_injection",
        "open_redirect",
        "information_leakage"
      ]
    },
    {
      id: "A.8.16",
      title: "Monitoring activities",
      description: "Evidence from scan run history, finding trends, and dismissal-reason audit data.",
      mappedFindingTypes: []
    },
    {
      id: "A.8.25",
      title: "Secure development life cycle",
      description: "Evidence from L1, L2, L3, and custom-rule checks integrated into developer and CI workflows.",
      mappedFindingTypes: ["missing_security_measure", "insecure_config", "ai_pattern_error", "sql_injection", "xss"]
    }
  ]
};

const disclaimer =
  "This is technical security evidence generated from VibeGuard scan history. It is not a certification, attestation, or proof of compliance.";

export function createComplianceReport(
  summary: FindingStoreSummary,
  options: ComplianceReportOptions = {}
): ComplianceReport {
  const generatedAt = options.generatedAt ?? Date.now();
  const frameworks = normalizeFrameworks(options.frameworks).map((framework) => ({
    framework,
    controls: controls[framework].map((control) => createControlEvidence(summary, control))
  }));
  return {
    generatedAt,
    period: {
      since: summary.since,
      until: generatedAt
    },
    disclaimer,
    summary: {
      project: summary.project,
      scanCount: summary.scanCount,
      findingCount: summary.findingCount,
      activeCount: summary.activeCount,
      dismissedCount: summary.dismissedCount,
      latestScanAt: summary.latestScanAt,
      latestScanDelta: summary.latestScanDelta
    },
    audit: {
      dismissalReasons: summary.dismissedReasonCounts.map((entry) => ({ reason: entry.key, count: entry.dismissedCount })),
      topRules: summary.topRules.map((entry) => ({
        rule: entry.key,
        count: entry.count,
        activeCount: entry.activeCount,
        falsePositiveCount: entry.falsePositiveCount,
        falsePositiveRate: entry.falsePositiveRate
      })),
      dashboardActions: summarizeDashboardActions(options.auditEvents ?? [])
    },
    frameworks
  };
}

export function formatComplianceMarkdown(report: ComplianceReport): string {
  const lines = [
    "# VibeGuard Security Evidence Report",
    "",
    `Generated: ${formatTimestamp(report.generatedAt)}`,
    `Reporting window: ${report.period.since ? `${formatTimestamp(report.period.since)} to ` : "All stored history to "}${formatTimestamp(report.period.until)}`,
    `Project scope: ${report.summary.project ? escapeMarkdownCell(report.summary.project) : "All projects"}`,
    "",
    `> ${report.disclaimer}`,
    "",
    "## Scan Summary",
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    `| Scan runs | ${report.summary.scanCount} |`,
    `| Findings | ${report.summary.findingCount} |`,
    `| Active findings | ${report.summary.activeCount} |`,
    `| Dismissed findings | ${report.summary.dismissedCount} |`,
    `| Latest scan | ${report.summary.latestScanAt ? formatTimestamp(report.summary.latestScanAt) : "None"} |`
  ];
  if (report.summary.latestScanDelta) {
    lines.push(
      `| New active risks in latest scan | ${report.summary.latestScanDelta.introducedCount} |`,
      `| Resolved active risks in latest scan | ${report.summary.latestScanDelta.resolvedCount} |`,
      `| Persistent active risks in latest scan | ${report.summary.latestScanDelta.persistentCount} |`
    );
  }

  for (const framework of report.frameworks) {
    lines.push("", `## ${frameworkName(framework.framework)}`, "");
    for (const control of framework.controls) {
      lines.push(`### ${control.id}: ${control.title}`, "", `Status: **${statusLabel(control.status)}**`, "", control.description, "");
      lines.push("| Evidence | Value |", "| --- | ---: |", `| Active mapped findings | ${control.activeFindingCount} |`);
      for (const evidence of control.evidence) {
        lines.push(`| ${escapeMarkdownCell(evidence.split(":")[0])} | ${escapeMarkdownCell(evidence.slice(evidence.indexOf(":") + 1).trim())} |`);
      }
    }
  }

  lines.push("", "## Audit Trail", "", "### Dismissal Reasons", "");
  if (report.audit.dismissalReasons.length === 0) {
    lines.push("No dismissed findings in this reporting window.");
  } else {
    lines.push("| Reason | Dismissed findings |", "| --- | ---: |");
    for (const reason of report.audit.dismissalReasons) {
      lines.push(`| ${escapeMarkdownCell(reason.reason)} | ${reason.count} |`);
    }
  }
  lines.push("", "### Top Detection Rules", "");
  if (report.audit.topRules.length === 0) {
    lines.push("No findings in this reporting window.");
  } else {
    lines.push("| Rule | Findings | Active | False positive | FP rate |", "| --- | ---: | ---: | ---: | ---: |");
    for (const rule of report.audit.topRules) {
      lines.push(
        `| ${escapeMarkdownCell(rule.rule)} | ${rule.count} | ${rule.activeCount} | ${rule.falsePositiveCount} | ${Math.round(rule.falsePositiveRate * 100)}% |`
      );
    }
  }
  lines.push("", "### Dashboard Audit Activity", "");
  if (report.audit.dashboardActions.length === 0) {
    lines.push("No dashboard audit events in this reporting window.");
  } else {
    lines.push("| Action | Outcome | Count |", "| --- | --- | ---: |");
    for (const event of report.audit.dashboardActions) {
      lines.push(`| ${escapeMarkdownCell(event.action)} | ${event.outcome} | ${event.count} |`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function createControlEvidence(summary: FindingStoreSummary, definition: ControlDefinition): ComplianceControlEvidence {
  const activeFindingCount = definition.mappedFindingTypes.length === 0
    ? summary.activeCount
    : definition.mappedFindingTypes.reduce(
        (total, type) => total + (summary.typeCounts.find((entry) => entry.key === type)?.activeCount ?? 0),
        0
      );
  const status: ComplianceControlStatus = summary.scanCount === 0 ? "not_assessed" : activeFindingCount > 0 ? "attention" : "observed";
  const evidence = [
    `Scan runs: ${summary.scanCount}`,
    `Active findings: ${activeFindingCount}`,
    `Trend points: ${summary.trend.length}`,
    `Dismissed findings: ${summary.dismissedCount}`
  ];
  if (summary.latestScanDelta) {
    evidence.push(
      `New active risks in latest scan: ${summary.latestScanDelta.introducedCount}`,
      `Resolved active risks in latest scan: ${summary.latestScanDelta.resolvedCount}`,
      `Persistent active risks in latest scan: ${summary.latestScanDelta.persistentCount}`
    );
  }
  return {
    id: definition.id,
    title: definition.title,
    status,
    description: definition.description,
    mappedFindingTypes: [...definition.mappedFindingTypes],
    activeFindingCount,
    evidence
  };
}

function normalizeFrameworks(value: ComplianceFramework[] | undefined): ComplianceFramework[] {
  const requested = value?.length ? value : ["soc2", "iso27001"];
  return [...new Set(requested)].filter((framework): framework is ComplianceFramework => framework === "soc2" || framework === "iso27001");
}

function frameworkName(framework: ComplianceFramework): string {
  return framework === "soc2" ? "SOC 2 Common Criteria Evidence" : "ISO/IEC 27001:2022 Evidence";
}

function statusLabel(status: ComplianceControlStatus): string {
  return status === "attention" ? "Attention needed" : status === "observed" ? "Evidence observed" : "Not assessed";
}

function formatTimestamp(value: number): string {
  return new Date(value).toISOString();
}

function escapeMarkdownCell(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function summarizeDashboardActions(events: StoredAuditEvent[]): Array<{ action: string; outcome: "success" | "denied"; count: number }> {
  const counts = new Map<string, { action: string; outcome: "success" | "denied"; count: number }>();
  for (const event of events) {
    const key = `${event.action}\u0000${event.outcome}`;
    const existing = counts.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      counts.set(key, { action: event.action, outcome: event.outcome, count: 1 });
    }
  }
  return [...counts.values()].sort((left, right) => right.count - left.count || left.action.localeCompare(right.action));
}

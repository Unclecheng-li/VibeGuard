import type { FindingStoreSummary, FindingSummaryBucket } from "./storage";
import type { Severity } from "../types";

export interface FindingsDashboardOptions {
  dbPath?: string;
  generatedAt?: number;
  title?: string;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function formatFindingsDashboard(summary: FindingStoreSummary, options: FindingsDashboardOptions = {}): string {
  const generatedAt = options.generatedAt ?? Date.now();
  const title = options.title ?? "VibeGuard Security Dashboard";
  const severityBuckets = severityOrder.map((severity) => bucketOrEmpty(summary.severityCounts, severity));
  const maxSeverityCount = Math.max(1, ...severityBuckets.map((bucket) => bucket.count));
  const maxTypeCount = Math.max(1, ...summary.typeCounts.map((bucket) => bucket.count));
  const maxDismissedReasonCount = Math.max(1, ...summary.dismissedReasonCounts.map((bucket) => bucket.count));
  const trendChart = renderTrendChart(summary);
  const riskLabel = riskPosture(summary);
  const activeRate = summary.findingCount === 0 ? 0 : Math.round((summary.activeCount / summary.findingCount) * 100);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --blue: #2266cc;
      --green: #168a5b;
      --amber: #b56a00;
      --red: #c92a2a;
      --violet: #6b4cc2;
      --cyan: #067a8f;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      line-height: 1.45;
    }
    main {
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 28px 0 36px;
    }
    header {
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: flex-end;
      margin-bottom: 22px;
    }
    h1, h2, p { margin: 0; }
    h1 {
      font-size: 30px;
      font-weight: 760;
      letter-spacing: 0;
    }
    h2 {
      font-size: 16px;
      font-weight: 720;
      margin-bottom: 12px;
    }
    .meta {
      color: var(--muted);
      font-size: 13px;
      text-align: right;
    }
    .grid {
      display: grid;
      gap: 14px;
    }
    .kpis {
      grid-template-columns: repeat(5, minmax(0, 1fr));
      margin-bottom: 14px;
    }
    .sections {
      grid-template-columns: minmax(0, 1.35fr) minmax(340px, 0.65fr);
      align-items: start;
    }
    .panel, .kpi {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(17, 24, 39, 0.04);
    }
    .panel { padding: 16px; }
    .kpi {
      min-height: 96px;
      padding: 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .kpi span {
      color: var(--muted);
      font-size: 12px;
      font-weight: 650;
      text-transform: uppercase;
    }
    .kpi strong {
      font-size: 28px;
      line-height: 1;
      letter-spacing: 0;
    }
    .kpi small { color: var(--muted); }
    .posture {
      border-left: 4px solid ${riskColor(summary)};
    }
    .chart {
      width: 100%;
      min-height: 250px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfe;
      overflow: hidden;
    }
    .bars {
      display: grid;
      gap: 10px;
    }
    .bar-row {
      display: grid;
      grid-template-columns: 86px minmax(0, 1fr) 68px;
      gap: 10px;
      align-items: center;
      font-size: 13px;
    }
    .bar-track {
      height: 12px;
      border-radius: 999px;
      background: #e8edf4;
      overflow: hidden;
    }
    .bar-fill {
      height: 100%;
      border-radius: 999px;
      background: var(--blue);
    }
    .critical { background: var(--red); }
    .high { background: #e45b38; }
    .medium { background: var(--amber); }
    .low { background: var(--cyan); }
    .info { background: var(--violet); }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      padding: 9px 8px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
    }
    td.num, th.num { text-align: right; }
    .empty {
      color: var(--muted);
      font-size: 13px;
      padding: 18px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      background: #fbfcfe;
    }
    .stack { display: grid; gap: 14px; }
    .rule { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; }
    footer {
      margin-top: 18px;
      color: var(--muted);
      font-size: 12px;
    }
    @media (max-width: 900px) {
      header { align-items: flex-start; flex-direction: column; }
      .meta { text-align: left; }
      .kpis, .sections { grid-template-columns: 1fr; }
      .bar-row { grid-template-columns: 74px minmax(0, 1fr) 54px; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>${escapeHtml(title)}</h1>
        <p class="meta" style="text-align:left">${escapeHtml(formatWindow(summary))}</p>
      </div>
      <p class="meta">Generated ${escapeHtml(formatDateTime(generatedAt))}${options.dbPath ? `<br>${escapeHtml(options.dbPath)}` : ""}</p>
    </header>

    <section class="grid kpis" aria-label="Finding totals">
      ${renderKpi("Risk posture", riskLabel, `${activeRate}% active`, "posture")}
      ${renderKpi("Scans", summary.scanCount, "scan runs")}
      ${renderKpi("Findings", summary.findingCount, "total")}
      ${renderKpi("Active", summary.activeCount, "open findings")}
      ${renderKpi("Dismissed", summary.dismissedCount, "audited findings")}
    </section>

    <section class="grid sections">
      <div class="stack">
        <section class="panel" aria-labelledby="trend-heading">
          <h2 id="trend-heading">Daily Finding Trend</h2>
          ${trendChart}
        </section>
        <section class="panel" aria-labelledby="rules-heading">
          <h2 id="rules-heading">Top Detection Rules</h2>
          ${renderRulesTable(summary)}
        </section>
        <section class="panel" aria-labelledby="authors-heading">
          <h2 id="authors-heading">Developer Risk</h2>
          ${renderAuthorsTable(summary)}
        </section>
      </div>
      <div class="stack">
        <section class="panel" aria-labelledby="severity-heading">
          <h2 id="severity-heading">Severity Distribution</h2>
          <div class="bars">
            ${severityBuckets.map((bucket) => renderSeverityBar(bucket, maxSeverityCount)).join("\n")}
          </div>
        </section>
        <section class="panel" aria-labelledby="dismissal-heading">
          <h2 id="dismissal-heading">Dismissal Reasons</h2>
          ${renderDismissalReasonsTable(summary, maxDismissedReasonCount)}
        </section>
        <section class="panel" aria-labelledby="type-heading">
          <h2 id="type-heading">Finding Types</h2>
          ${renderTypeTable(summary, maxTypeCount)}
        </section>
      </div>
    </section>
    <script type="application/json" id="vibeguard-summary">${escapeJsonScript(summary)}</script>
    <footer>VibeGuard dashboard export. Counts include active and dismissed findings stored in the local findings database.</footer>
  </main>
</body>
</html>`;
}

function renderKpi(label: string, value: string | number, helper: string, className = ""): string {
  return `<div class="kpi ${className}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong><small>${escapeHtml(helper)}</small></div>`;
}

function renderSeverityBar(bucket: FindingSummaryBucket, maxCount: number): string {
  const width = Math.round((bucket.count / maxCount) * 100);
  return `<div class="bar-row">
    <span>${escapeHtml(labelCase(bucket.key))}</span>
    <div class="bar-track"><div class="bar-fill ${escapeHtml(bucket.key)}" style="width:${width}%"></div></div>
    <span>${bucket.count}</span>
  </div>`;
}

function renderDismissalReasonsTable(summary: FindingStoreSummary, maxCount: number): string {
  if (summary.dismissedReasonCounts.length === 0) {
    return `<div class="empty">No dismissed findings recorded yet.</div>`;
  }
  const rows = summary.dismissedReasonCounts
    .map((bucket) => {
      const width = Math.round((bucket.count / maxCount) * 100);
      return `<tr>
        <td>${escapeHtml(bucket.key)}</td>
        <td><div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div></td>
        <td class="num">${bucket.count}</td>
      </tr>`;
    })
    .join("\n");
  return `<table>
    <thead><tr><th>Reason</th><th>Share</th><th class="num">Dismissed</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderTypeTable(summary: FindingStoreSummary, maxCount: number): string {
  if (summary.typeCounts.length === 0) {
    return `<div class="empty">No finding types recorded yet.</div>`;
  }
  const rows = summary.typeCounts
    .map((bucket) => {
      const width = Math.round((bucket.count / maxCount) * 100);
      return `<tr>
        <td>${escapeHtml(bucket.key)}</td>
        <td><div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div></td>
        <td class="num">${bucket.count}</td>
        <td class="num">${bucket.activeCount}</td>
      </tr>`;
    })
    .join("\n");
  return `<table>
    <thead><tr><th>Type</th><th>Share</th><th class="num">Total</th><th class="num">Active</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderRulesTable(summary: FindingStoreSummary): string {
  if (summary.topRules.length === 0) {
    return `<div class="empty">No detection rules recorded yet.</div>`;
  }
  const rows = summary.topRules
    .map(
      (rule) => `<tr>
        <td class="rule">${escapeHtml(rule.key)}</td>
        <td>${escapeHtml(rule.severity)}</td>
        <td>${escapeHtml(rule.type)}</td>
        <td class="num">${rule.count}</td>
        <td class="num">${rule.activeCount}</td>
        <td class="num">${rule.dismissedCount}</td>
      </tr>`
    )
    .join("\n");
  return `<table>
    <thead><tr><th>Rule</th><th>Severity</th><th>Type</th><th class="num">Total</th><th class="num">Active</th><th class="num">Dismissed</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderAuthorsTable(summary: FindingStoreSummary): string {
  if (summary.authorCounts.length === 0) {
    return `<div class="empty">No git author attribution recorded yet.</div>`;
  }
  const rows = summary.authorCounts
    .map((author) => {
      const label = author.name && author.email ? `${author.name} <${author.email}>` : author.name ?? author.email ?? author.key;
      return `<tr>
        <td>${escapeHtml(label)}</td>
        <td class="num">${author.count}</td>
        <td class="num">${author.activeCount}</td>
        <td class="num">${author.highRiskCount}</td>
        <td class="num">${Math.round(author.highRiskRate * 100)}%</td>
      </tr>`;
    })
    .join("\n");
  return `<table>
    <thead><tr><th>Author</th><th class="num">Total</th><th class="num">Active</th><th class="num">Critical/High</th><th class="num">High-Risk Rate</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderTrendChart(summary: FindingStoreSummary): string {
  if (summary.trend.length === 0) {
    return `<div class="empty">No trend data recorded yet. Run scans with findings storage enabled to populate this dashboard.</div>`;
  }
  const width = 780;
  const height = 260;
  const padding = { top: 22, right: 22, bottom: 42, left: 42 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const maxFindings = Math.max(1, ...summary.trend.map((point) => point.findingCount));
  const step = chartWidth / Math.max(1, summary.trend.length);
  const barWidth = Math.min(42, Math.max(14, step * 0.56));
  const gridLines = [0, 0.25, 0.5, 0.75, 1];
  const grid = gridLines
    .map((ratio) => {
      const y = padding.top + chartHeight - chartHeight * ratio;
      const value = Math.round(maxFindings * ratio);
      return `<line x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" stroke="#d9dee7" stroke-width="1"/><text x="12" y="${y + 4}" fill="#5f6b7a" font-size="11">${value}</text>`;
    })
    .join("");
  const bars = summary.trend
    .map((point, index) => {
      const x = padding.left + index * step + (step - barWidth) / 2;
      const activeHeight = (point.activeCount / maxFindings) * chartHeight;
      const dismissedHeight = (point.dismissedCount / maxFindings) * chartHeight;
      const activeY = padding.top + chartHeight - activeHeight;
      const dismissedY = activeY - dismissedHeight;
      const label = labelTrendDate(point.date, summary.trend.length, index);
      return `<g>
        <rect x="${x.toFixed(1)}" y="${activeY.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${activeHeight.toFixed(1)}" fill="#2266cc" rx="3"/>
        <rect x="${x.toFixed(1)}" y="${dismissedY.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${dismissedHeight.toFixed(1)}" fill="#a7b0bd" rx="3"/>
        ${label ? `<text x="${(x + barWidth / 2).toFixed(1)}" y="${height - 18}" text-anchor="middle" fill="#5f6b7a" font-size="11">${escapeHtml(label)}</text>` : ""}
      </g>`;
    })
    .join("");
  return `<div class="chart">
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Daily active and dismissed findings trend" width="100%" height="100%" preserveAspectRatio="none">
      <rect x="0" y="0" width="${width}" height="${height}" fill="#fbfcfe"/>
      ${grid}
      <line x1="${padding.left}" y1="${padding.top + chartHeight}" x2="${width - padding.right}" y2="${padding.top + chartHeight}" stroke="#9aa4b2"/>
      ${bars}
      <circle cx="${width - 184}" cy="18" r="5" fill="#2266cc"/><text x="${width - 174}" y="22" fill="#5f6b7a" font-size="12">active</text>
      <circle cx="${width - 104}" cy="18" r="5" fill="#a7b0bd"/><text x="${width - 94}" y="22" fill="#5f6b7a" font-size="12">dismissed</text>
    </svg>
  </div>`;
}

function bucketOrEmpty(buckets: FindingSummaryBucket[], key: string): FindingSummaryBucket {
  return buckets.find((bucket) => bucket.key === key) ?? { key, count: 0, activeCount: 0, dismissedCount: 0 };
}

function riskPosture(summary: FindingStoreSummary): string {
  const critical = bucketOrEmpty(summary.severityCounts, "critical").activeCount;
  const high = bucketOrEmpty(summary.severityCounts, "high").activeCount;
  if (critical > 0) {
    return "Critical";
  }
  if (high > 0) {
    return "High";
  }
  if (summary.activeCount > 0) {
    return "Watch";
  }
  return "Clear";
}

function riskColor(summary: FindingStoreSummary): string {
  const posture = riskPosture(summary);
  if (posture === "Critical" || posture === "High") {
    return "var(--red)";
  }
  if (posture === "Watch") {
    return "var(--amber)";
  }
  return "var(--green)";
}

function formatWindow(summary: FindingStoreSummary): string {
  if (!summary.since) {
    return "All stored scan history";
  }
  return `Since ${formatDateTime(summary.since)}`;
}

function formatDateTime(timestamp: number): string {
  return new Date(timestamp).toISOString();
}

function labelTrendDate(date: string, total: number, index: number): string {
  if (total > 14 && index !== 0 && index !== total - 1 && index % Math.ceil(total / 6) !== 0) {
    return "";
  }
  return date.slice(5);
}

function labelCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b[a-z]/g, (match) => match.toUpperCase());
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeJsonScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

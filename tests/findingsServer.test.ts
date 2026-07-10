import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { startFindingsDashboardServer } from "../src/findings/server";
import { isFindingsStorageAvailable, SqliteFindingStore } from "../src/findings/storage";
import type { Finding } from "../src/types";

test("serves team dashboard HTML and token-protected summaries", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-dashboard-server-"));
  const dbPath = path.join(directory, "findings.db");
  const store = new SqliteFindingStore(dbPath);
  store.recordScanRun({
    scanId: "team_scan",
    startedAt: 1,
    completedAt: 2,
    cwd: directory,
    targetPaths: ["app.ts"],
    fileCount: 1,
    findings: [finding()]
  });
  store.close();

  const dashboard = await startFindingsDashboardServer({ dbPath, port: 0, token: "team-secret", title: "Example Team" });
  try {
    const unauthorized = await fetch(dashboard.url);
    assert.equal(unauthorized.status, 401);

    const html = await fetch(dashboard.url, { headers: { authorization: "Bearer team-secret" } });
    assert.equal(html.status, 200);
    assert.match(await html.text(), /Example Team/);

    const summary = await fetch(new URL("api/summary", dashboard.url), { headers: { authorization: "Bearer team-secret" } });
    assert.equal(summary.status, 200);
    assert.equal((await summary.json() as { findingCount: number }).findingCount, 1);

    const health = await fetch(new URL("healthz", dashboard.url));
    assert.equal(health.status, 200);
  } finally {
    await dashboard.close();
  }
});

function finding(): Finding {
  return {
    id: "team_finding",
    type: "sql_injection",
    severity: "high",
    message: "Query interpolates input.",
    file: "app.ts",
    line: 1,
    column: 1,
    evidence: "query",
    detection_layer: "L2",
    detection_rule: "sast_sql_template_interpolation",
    timestamp: 1,
    dismissed: false
  };
}

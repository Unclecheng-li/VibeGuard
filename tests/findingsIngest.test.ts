import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { createFindingsIngestPayload, parseFindingsIngestPayload } from "../src/findings/ingest";
import { uploadFindings } from "../src/findings/ingestClient";
import { startFindingsDashboardServer } from "../src/findings/server";
import { isFindingsStorageAvailable, SqliteFindingStore, type RecordScanRunInput } from "../src/findings/storage";
import type { Finding } from "../src/types";

const execFileAsync = promisify(execFile);

test("ingests CI scan results with a separate token and records an audit event", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-findings-ingest-"));
  const dbPath = path.join(directory, "findings.db");
  const dashboard = await startFindingsDashboardServer({
    dbPath,
    port: 0,
    ingestToken: "ingest-secret",
    ingestMaxFindings: 1
  });
  const scan = scanInput();
  scan.project = "acme/payments-api";
  const endpoint = new URL("api/ingest", dashboard.url).toString();
  try {
    const unauthorized = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(createFindingsIngestPayload(scan))
    });
    assert.equal(unauthorized.status, 401);

    const uploaded = await uploadFindings({
      endpoint,
      token: "ingest-secret",
      scan
    });
    assert.equal(uploaded.scanId, "ci-run-17");
    assert.equal(uploaded.findingCount, 1);
    assert.equal(uploaded.activeCount, 1);

    const summary = await fetch(new URL("api/summary?project=acme%2Fpayments-api", dashboard.url));
    assert.equal(summary.status, 200);
    const filteredSummary = await summary.json() as { findingCount: number; project?: string };
    assert.equal(filteredSummary.findingCount, 1);
    assert.equal(filteredSummary.project, "acme/payments-api");

    const audit = await fetch(new URL("api/audit", dashboard.url));
    const events = await audit.json() as Array<{ action: string; authentication: string; details: Record<string, unknown> }>;
    const ingestEvent = events.find((event) => event.action === "findings.ingested");
    assert.equal(ingestEvent?.authentication, "ingest");
    assert.deepEqual(ingestEvent?.details, { finding_count: 1, file_count: 1 });

    const tooMany = await fetch(endpoint, {
      method: "POST",
      headers: {
        authorization: "Bearer ingest-secret",
        "content-type": "application/json"
      },
      body: JSON.stringify(createFindingsIngestPayload({ ...scan, scanId: "ci-run-18", findings: [finding(), finding({ id: "two" })] }))
    });
    assert.equal(tooMany.status, 413);
  } finally {
    await dashboard.close();
  }
});

test("rejects malformed network ingest payloads before they reach storage", () => {
  const invalid = createFindingsIngestPayload(scanInput());
  invalid.schema = "unexpected.schema" as typeof invalid.schema;
  assert.throws(() => parseFindingsIngestPayload(invalid), /payload\.schema/);

  const unknownAuthor = createFindingsIngestPayload({
    ...scanInput(),
    findingAuthors: { absent: { name: "Unknown" } }
  });
  assert.throws(() => parseFindingsIngestPayload(unknownAuthor), /unknown finding id/);

  const backwardsTime = createFindingsIngestPayload({ ...scanInput(), startedAt: 3, completedAt: 2 });
  assert.throws(() => parseFindingsIngestPayload(backwardsTime), /completedAt must not be earlier/);
});

test("does not send an ingest bearer token to a non-local HTTP endpoint", async () => {
  await assert.rejects(
    uploadFindings({
      endpoint: "http://dashboard.example.test/api/ingest",
      token: "ingest-secret",
      scan: scanInput(),
      fetcher: async () => {
        throw new Error("fetch should not be called");
      }
    }),
    /must use HTTPS/
  );
});

test("manages project-scoped ingest credentials and confines CI uploads to their project", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }

  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-project-ingest-"));
  const dashboard = await startFindingsDashboardServer({
    dbPath: path.join(directory, "findings.db"),
    port: 0,
    token: "dashboard-admin-token"
  });
  const projectsEndpoint = new URL("api/projects", dashboard.url);
  const ingestEndpoint = new URL("api/ingest", dashboard.url);
  const adminHeaders = {
    authorization: "Bearer dashboard-admin-token",
    "content-type": "application/json"
  };
  try {
    assert.equal((await fetch(projectsEndpoint)).status, 401);

    const createdResponse = await fetch(projectsEndpoint, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ project: "acme/payments-api" })
    });
    assert.equal(createdResponse.status, 201);
    const created = await createdResponse.json() as { project: string; token: string; created: boolean };
    assert.equal(created.project, "acme/payments-api");
    assert.equal(created.created, true);
    assert.match(created.token, /^vgpi_/);

    const listedResponse = await fetch(projectsEndpoint, { headers: { authorization: "Bearer dashboard-admin-token" } });
    assert.equal(listedResponse.status, 200);
    const listed = await listedResponse.json() as Array<{ project: string; token?: string }>;
    assert.deepEqual(listed.map((item) => item.project), ["acme/payments-api"]);
    assert.equal("token" in listed[0], false);

    const duplicate = await fetch(projectsEndpoint, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ project: "acme/payments-api" })
    });
    assert.equal(duplicate.status, 409);

    const allowedScan = { ...scanInput(), project: "acme/payments-api" };
    const allowed = await fetch(ingestEndpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${created.token}`, "content-type": "application/json" },
      body: JSON.stringify(createFindingsIngestPayload(allowedScan))
    });
    assert.equal(allowed.status, 201);

    const crossProject = await fetch(ingestEndpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${created.token}`, "content-type": "application/json" },
      body: JSON.stringify(createFindingsIngestPayload({ ...scanInput(), scanId: "cross-project", project: "acme/other" }))
    });
    assert.equal(crossProject.status, 403);

    const rotatedResponse = await fetch(projectsEndpoint, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ project: "acme/payments-api", rotate: true })
    });
    assert.equal(rotatedResponse.status, 200);
    const rotated = await rotatedResponse.json() as { token: string; created: boolean };
    assert.equal(rotated.created, false);
    assert.notEqual(rotated.token, created.token);

    const oldToken = await fetch(ingestEndpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${created.token}`, "content-type": "application/json" },
      body: JSON.stringify(createFindingsIngestPayload({ ...allowedScan, scanId: "old-token" }))
    });
    assert.equal(oldToken.status, 401);

    const newToken = await fetch(ingestEndpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${rotated.token}`, "content-type": "application/json" },
      body: JSON.stringify(createFindingsIngestPayload({ ...allowedScan, scanId: "new-token" }))
    });
    assert.equal(newToken.status, 201);

    const revokedResponse = await fetch(new URL("api/projects?project=acme%2Fpayments-api", dashboard.url), {
      method: "DELETE",
      headers: { authorization: "Bearer dashboard-admin-token" }
    });
    assert.equal(revokedResponse.status, 200);
    const revokedToken = await fetch(ingestEndpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${rotated.token}`, "content-type": "application/json" },
      body: JSON.stringify(createFindingsIngestPayload({ ...allowedScan, scanId: "revoked-token" }))
    });
    assert.equal(revokedToken.status, 401);

    const auditResponse = await fetch(new URL("api/audit", dashboard.url), {
      headers: { authorization: "Bearer dashboard-admin-token" }
    });
    const audit = await auditResponse.json() as Array<{ action: string }>;
    const serializedAudit = JSON.stringify(audit);
    assert.equal(serializedAudit.includes(created.token), false);
    assert.equal(serializedAudit.includes(rotated.token), false);
    assert.equal(audit.some((event) => event.action === "dashboard.project_ingest_configured"), true);
    assert.equal(audit.some((event) => event.action === "dashboard.project_ingest_revoked"), true);
  } finally {
    await dashboard.close();
  }
});

test("CLI uploads a completed scan when a private findings endpoint is configured", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-cli-ingest-"));
  const sourcePath = path.join(directory, "app.ts");
  await fs.writeFile(sourcePath, "const result = eval(userInput);\n", "utf8");
  const dashboard = await startFindingsDashboardServer({
    dbPath: path.join(directory, "findings.db"),
    port: 0,
    ingestToken: "cli-ingest-secret"
  });
  try {
    await execFileAsync(
      process.execPath,
      [
        path.resolve(process.cwd(), "out", "src", "cli.js"),
        "scan",
        sourcePath,
        "--package-verification",
        "off",
        "--no-l2",
        "--no-config",
        "--no-ignore",
        "--no-store-findings",
        "--findings-endpoint",
        new URL("api/ingest", dashboard.url).toString(),
        "--findings-project",
        "acme/cli-sample",
        "--findings-upload-required",
        "--fail-on",
        "none"
      ],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          VIBEGUARD_FINDINGS_INGEST_TOKEN: "cli-ingest-secret"
        }
      }
    );
    const summary = await fetch(new URL("api/summary?project=acme%2Fcli-sample", dashboard.url));
    const result = await summary.json() as { scanCount: number; project?: string };
    assert.equal(result.scanCount, 1);
    assert.equal(result.project, "acme/cli-sample");
  } finally {
    await dashboard.close();
  }
});

function scanInput(): RecordScanRunInput {
  return {
    scanId: "ci-run-17",
    startedAt: 1,
    completedAt: 2,
    cwd: "/workspace",
    targetPaths: ["/workspace/app.ts"],
    fileCount: 1,
    findings: [finding()],
    findingAuthors: {
      finding: { name: "Ada Lovelace", email: "ada@example.com" }
    }
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding",
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
    dismissed: false,
    ...overrides
  };
}

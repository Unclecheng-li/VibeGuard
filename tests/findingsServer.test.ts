import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { startFindingsDashboardServer } from "../src/findings/server";
import { isFindingsStorageAvailable, SqliteFindingStore } from "../src/findings/storage";
import { cliFalsePositiveTelemetryEvent } from "../src/telemetry";
import type { Finding } from "../src/types";

test("rejects an unsafe OIDC public URL before opening dashboard storage", async () => {
  await assert.rejects(
    startFindingsDashboardServer({
      dbPath: path.join(os.tmpdir(), "vibeguard-should-not-open.db"),
      oidc: {
        issuer: "https://id.example.test",
        clientId: "vibeguard-dashboard",
        sessionSecret: "dashboard-session-secret-with-at-least-32-bytes",
        publicUrl: "http://dashboard.example.test"
      }
    }),
    /OIDC dashboard public URL must use HTTPS outside localhost development\./
  );
});

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
    project: "acme/payments-api",
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

    const malformedCookie = await fetch(dashboard.url, { headers: { cookie: "vibeguard_team_token=%" } });
    assert.equal(malformedCookie.status, 401);

    const tokenLogin = await fetch(new URL("?token=team-secret&project=acme%2Fpayments-api", dashboard.url), { redirect: "manual" });
    assert.equal(tokenLogin.status, 302);
    assert.equal(tokenLogin.headers.get("location"), "/?project=acme%2Fpayments-api");
    assert.match(tokenLogin.headers.get("set-cookie") ?? "", /HttpOnly; SameSite=Strict; Path=\/$/);
    const tokenCookie = cookieFromHeaders(tokenLogin.headers, "vibeguard_team_token");
    const tokenDashboard = await fetch(new URL(tokenLogin.headers.get("location") ?? "", dashboard.url), {
      headers: { cookie: tokenCookie }
    });
    assert.equal(tokenDashboard.status, 200);

    const html = await fetch(dashboard.url, { headers: { authorization: "Bearer team-secret" } });
    assert.equal(html.status, 200);
    assert.equal(html.headers.get("x-frame-options"), "DENY");
    assert.match(html.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
    const dashboardHtml = await html.text();
    assert.match(dashboardHtml, /Example Team/);
    assert.match(dashboardHtml, /Project integrations/);
    assert.match(dashboardHtml, /href="\/\?project=acme%2Fpayments-api"/);

    const filteredDashboard = await fetch(new URL("?project=acme%2Fpayments-api", dashboard.url), {
      headers: { authorization: "Bearer team-secret" }
    });
    assert.equal(filteredDashboard.status, 200);
    assert.match(await filteredDashboard.text(), /href="\/">All projects/);

    const projectPage = await fetch(new URL("projects", dashboard.url), { headers: { authorization: "Bearer team-secret" } });
    assert.equal(projectPage.status, 200);
    assert.match(await projectPage.text(), /Create Credential/);

    const summary = await fetch(new URL("api/summary", dashboard.url), { headers: { authorization: "Bearer team-secret" } });
    assert.equal(summary.status, 200);
    assert.equal((await summary.json() as { findingCount: number }).findingCount, 1);

    const compliance = await fetch(new URL("api/compliance?framework=soc2", dashboard.url), {
      headers: { authorization: "Bearer team-secret" }
    });
    assert.equal(compliance.status, 200);
    assert.deepEqual((await compliance.json() as { frameworks: Array<{ framework: string }> }).frameworks.map((item) => item.framework), ["soc2"]);

    const audit = await fetch(new URL("api/audit", dashboard.url), { headers: { authorization: "Bearer team-secret" } });
    assert.equal(audit.status, 200);
    assert.equal((await audit.json() as Array<{ action: string }>).some((event) => event.action === "dashboard.compliance_viewed"), true);

    const health = await fetch(new URL("healthz", dashboard.url));
    assert.equal(health.status, 200);
  } finally {
    await dashboard.close();
  }
});

test("collects only bounded anonymous false-positive telemetry when explicitly enabled", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-telemetry-server-"));
  const dbPath = path.join(directory, "findings.db");
  const disabled = await startFindingsDashboardServer({ dbPath, port: 0, token: "team-secret" });
  try {
    const unavailable = await fetch(new URL("api/telemetry/false-positive", disabled.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cliFalsePositiveTelemetryEvent("rule", "cli", "global"))
    });
    assert.equal(unavailable.status, 404);
  } finally {
    await disabled.close();
  }

  const dashboard = await startFindingsDashboardServer({
    dbPath,
    port: 0,
    token: "team-secret",
    telemetryCollection: true,
    telemetryMaxEventsPerMinute: 3
  });
  const event = cliFalsePositiveTelemetryEvent("internal_rule_name", "cli", "global");
  try {
    const invalid = await fetch(new URL("api/telemetry/false-positive", dashboard.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...event, path: "/private/app.ts" })
    });
    assert.equal(invalid.status, 400);

    const oversized = await fetch(new URL("api/telemetry/false-positive", dashboard.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(2048) })
    });
    assert.equal(oversized.status, 413);

    const accepted = await fetch(new URL("api/telemetry/false-positive", dashboard.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event)
    });
    assert.equal(accepted.status, 202);
    assert.deepEqual(await accepted.json(), { accepted: true });

    const limited = await fetch(new URL("api/telemetry/false-positive", dashboard.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event)
    });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "60");

    const summary = await fetch(new URL("api/summary", dashboard.url), {
      headers: { authorization: "Bearer team-secret" }
    });
    assert.equal(summary.status, 200);
    const feedback = (await summary.json() as {
      anonymousFalsePositiveTelemetry?: Array<{
        ruleFingerprint: string;
        eventCount: number;
        sources: string[];
        scopes: string[];
        firstReceivedAt: number;
        lastReceivedAt: number;
      }>;
    }).anonymousFalsePositiveTelemetry;
    assert.equal(feedback?.length, 1);
    assert.equal(feedback?.[0]?.ruleFingerprint, event.ruleFingerprint);
    assert.equal(feedback?.[0]?.eventCount, 1);
    assert.deepEqual(feedback?.[0]?.sources, ["cli"]);
    assert.deepEqual(feedback?.[0]?.scopes, ["global"]);
    assert.ok((feedback?.[0]?.lastReceivedAt ?? 0) >= (feedback?.[0]?.firstReceivedAt ?? 0));
    assert.equal(JSON.stringify(feedback).includes("internal_rule_name"), false);
  } finally {
    await dashboard.close();
  }
});

test("administers project custom rules and limits downloads to the matching CI credential", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-project-rules-server-"));
  const dbPath = path.join(directory, "findings.db");
  const store = new SqliteFindingStore(dbPath);
  const credential = store.issueProjectIngestCredential("acme/payments-api");
  assert.ok(credential);
  store.close();

  const dashboard = await startFindingsDashboardServer({ dbPath, port: 0, token: "team-secret" });
  const yaml = `rules:
  - id: company_no_example
    pattern: example-insecure-setting
    severity: medium
    type: insecure_config
    layer: L1
    message: Use the approved configuration.
`;
  try {
    const saved = await fetch(new URL("api/project-rules", dashboard.url), {
      method: "PUT",
      headers: { authorization: "Bearer team-secret", "content-type": "application/json" },
      body: JSON.stringify({ project: "acme/payments-api", yaml })
    });
    assert.equal(saved.status, 200);
    const savedRules = await saved.json() as { project: string; yaml: string; ruleCount: number; updatedAt: number };
    assert.equal(savedRules.project, "acme/payments-api");
    assert.equal(savedRules.yaml, yaml);
    assert.equal(savedRules.ruleCount, 1);
    assert.ok(savedRules.updatedAt > 0);

    const listed = await fetch(new URL("api/project-rules", dashboard.url), { headers: { authorization: "Bearer team-secret" } });
    assert.equal(listed.status, 200);
    const rules = await listed.json() as Array<{ project: string; ruleCount: number; updatedAt: number; yaml?: string }>;
    assert.deepEqual(rules.map((rule) => ({ project: rule.project, ruleCount: rule.ruleCount })), [{ project: "acme/payments-api", ruleCount: 1 }]);
    assert.equal("yaml" in rules[0], false);

    const downloaded = await fetch(new URL("api/project-rules/download?project=acme%2Fpayments-api", dashboard.url), {
      headers: { authorization: `Bearer ${credential.token}` }
    });
    assert.equal(downloaded.status, 200);
    assert.match(downloaded.headers.get("content-type") ?? "", /^text\/yaml/);
    assert.equal(await downloaded.text(), yaml);

    const crossProject = await fetch(new URL("api/project-rules/download?project=acme%2Fother", dashboard.url), {
      headers: { authorization: `Bearer ${credential.token}` }
    });
    assert.equal(crossProject.status, 403);

    const invalid = await fetch(new URL("api/project-rules", dashboard.url), {
      method: "PUT",
      headers: { authorization: "Bearer team-secret", "content-type": "application/json" },
      body: JSON.stringify({ project: "acme/payments-api", yaml: "rules: invalid" })
    });
    assert.equal(invalid.status, 400);

    const deleted = await fetch(new URL("api/project-rules?project=acme%2Fpayments-api", dashboard.url), {
      method: "DELETE",
      headers: { authorization: "Bearer team-secret" }
    });
    assert.equal(deleted.status, 200);
    const unavailable = await fetch(new URL("api/project-rules/download?project=acme%2Fpayments-api", dashboard.url), {
      headers: { authorization: `Bearer ${credential.token}` }
    });
    assert.equal(unavailable.status, 404);
  } finally {
    await dashboard.close();
  }
});

test("uses OIDC PKCE sign-in and enforces dashboard roles", async (context) => {
  if (!isFindingsStorageAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-oidc-dashboard-"));
  const dbPath = path.join(directory, "findings.db");
  const store = new SqliteFindingStore(dbPath);
  store.recordScanRun({
    scanId: "oidc_scan",
    startedAt: 1,
    completedAt: 2,
    cwd: directory,
    targetPaths: ["app.ts"],
    fileCount: 1,
    findings: [finding()]
  });
  store.close();

  const issuer = "https://id.example.test";
  const sessionSecret = "dashboard-session-secret-with-at-least-32-bytes";
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key", use: "sig", alg: "RS256" };
  let exchangedBody = "";
  const dashboard = await startFindingsDashboardServer({
    dbPath,
    port: 0,
    token: "break-glass-token",
    oidc: {
      issuer,
      clientId: "vibeguard-dashboard",
      sessionSecret,
      publicUrl: "https://guard.example.test",
      roleMappings: { "security-analysts": "analyst" },
      fetcher: async (input, init) => {
        const target = String(input);
        if (target === `${issuer}/.well-known/openid-configuration`) {
          return jsonResponse({
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            jwks_uri: `${issuer}/keys`
          });
        }
        if (target === `${issuer}/keys`) {
          return jsonResponse({ keys: [jwk] });
        }
        if (target === `${issuer}/token`) {
          exchangedBody = String(init?.body ?? "");
          const parameters = new URLSearchParams(exchangedBody);
          const stateCookie = parameters.get("code_verifier");
          assert.ok(stateCookie);
          return jsonResponse({
            id_token: signedIdToken(privateKey, {
              iss: issuer,
              aud: "vibeguard-dashboard",
              sub: "analyst-7",
              nonce: activeNonce,
              exp: Math.floor(Date.now() / 1000) + 60,
              roles: ["security-analysts"]
            })
          });
        }
        throw new Error(`Unexpected OIDC request: ${target}`);
      }
    }
  });
  let activeNonce = "";
  try {
    const serviceTokenLogin = await fetch(new URL("?token=break-glass-token", dashboard.url), { redirect: "manual" });
    assert.equal(serviceTokenLogin.status, 302);
    assert.equal(serviceTokenLogin.headers.get("location"), "/");
    assert.match(serviceTokenLogin.headers.get("set-cookie") ?? "", /HttpOnly; SameSite=Strict; Path=\/; Secure/);

    const projectRootLogin = await fetch(new URL("?project=acme%2Fpayments-api", dashboard.url), { redirect: "manual" });
    assert.equal(projectRootLogin.status, 302);
    const projectReturn = new URL(projectRootLogin.headers.get("location") ?? "", dashboard.url);
    assert.equal(projectReturn.pathname, "/auth/login");
    assert.equal(projectReturn.searchParams.get("returnTo"), "/?project=acme%2Fpayments-api");

    const login = await fetch(new URL("auth/login?returnTo=/api/findings", dashboard.url), { redirect: "manual" });
    assert.equal(login.status, 302);
    const loginLocation = new URL(login.headers.get("location") ?? "");
    assert.equal(loginLocation.origin, issuer);
    assert.equal(loginLocation.searchParams.get("redirect_uri"), "https://guard.example.test/auth/callback");
    assert.equal(loginLocation.searchParams.get("code_challenge_method"), "S256");
    assert.ok(loginLocation.searchParams.get("code_challenge"));

    const stateCookie = cookieFromHeaders(login.headers, "vibeguard_oidc_state");
    const signedState = decodeURIComponent(stateCookie.split("=")[1]);
    const statePayload = JSON.parse(Buffer.from(signedState.split(".")[0], "base64url").toString("utf8")) as {
      state: string;
      nonce: string;
    };
    activeNonce = statePayload.nonce;

    const callback = await fetch(
      new URL(`auth/callback?code=sample-code&state=${encodeURIComponent(statePayload.state)}`, dashboard.url),
      { headers: { cookie: stateCookie }, redirect: "manual" }
    );
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get("location"), "/api/findings");
    assert.match(exchangedBody, /code_verifier=/);
    assert.match(exchangedBody, /client_id=vibeguard-dashboard/);
    const sessionCookie = cookieFromHeaders(callback.headers, "vibeguard_team_session");

    const session = await fetch(new URL("api/session", dashboard.url), { headers: { cookie: sessionCookie } });
    assert.equal(session.status, 200);
    assert.deepEqual(await session.json(), {
      subject: "analyst-7",
      role: "analyst",
      authentication: "oidc"
    });
    const analystFindings = await fetch(new URL("api/findings", dashboard.url), { headers: { cookie: sessionCookie } });
    assert.equal(analystFindings.status, 200);
    const analystCompliance = await fetch(new URL("api/compliance", dashboard.url), { headers: { cookie: sessionCookie } });
    assert.equal(analystCompliance.status, 200);
    const analystAudit = await fetch(new URL("api/audit", dashboard.url), { headers: { cookie: sessionCookie } });
    assert.equal(analystAudit.status, 403);
    const analystProjects = await fetch(new URL("api/projects", dashboard.url), { headers: { cookie: sessionCookie } });
    assert.equal(analystProjects.status, 403);
    const analystProjectPage = await fetch(new URL("projects", dashboard.url), { headers: { cookie: sessionCookie } });
    assert.equal(analystProjectPage.status, 403);

    const viewerSession = signedDashboardSession({ sub: "viewer-1", role: "viewer", exp: Math.floor(Date.now() / 1000) + 60 }, sessionSecret);
    const denied = await fetch(new URL("api/findings", dashboard.url), { headers: { cookie: viewerSession } });
    assert.equal(denied.status, 403);
    const deniedCompliance = await fetch(new URL("api/compliance", dashboard.url), { headers: { cookie: viewerSession } });
    assert.equal(deniedCompliance.status, 403);

    const logout = await fetch(new URL("auth/logout", dashboard.url), { headers: { cookie: sessionCookie }, redirect: "manual" });
    assert.equal(logout.status, 302);

    const audit = await fetch(new URL("api/audit", dashboard.url), {
      headers: { authorization: "Bearer break-glass-token" }
    });
    assert.equal(audit.status, 200);
    const actions = (await audit.json() as Array<{ action: string }>).map((event) => event.action);
    assert.equal(actions.includes("dashboard.sign_in"), true);
    assert.equal(actions.includes("dashboard.sign_out"), true);
    assert.equal(actions.includes("dashboard.access_denied"), true);
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

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
}

function signedIdToken(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], claims: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
}

function cookieFromHeaders(headers: Headers, name: string): string {
  const value = headers.get("set-cookie") ?? "";
  const match = value.match(new RegExp(`(${name}=[^;]+)`));
  assert.ok(match, `Expected ${name} cookie in ${value}`);
  return match[1];
}

function signedDashboardSession(value: Record<string, unknown>, secret: string): string {
  const payload = Buffer.from(JSON.stringify(value)).toString("base64url");
  const signature = createHmac("sha256", secret).update(payload).digest("base64url");
  return `vibeguard_team_session=${encodeURIComponent(`${payload}.${signature}`)}`;
}

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

test("private deployment Compose files keep the dashboard local by default and require separate tokens", async () => {
  const [baseRaw, oidcRaw, envExample, ci] = await Promise.all([
    fs.readFile("deploy/compose.yaml", "utf8"),
    fs.readFile("deploy/compose.oidc.yaml", "utf8"),
    fs.readFile("deploy/.env.example", "utf8"),
    fs.readFile(".github/workflows/ci.yml", "utf8")
  ]);
  const base = parse(baseRaw) as {
    name: string;
    services: {
      dashboard: {
        command: string[];
        environment: Record<string, string>;
        ports: string[];
        volumes: string[];
        healthcheck: { test: string[] };
        restart: string;
        security_opt: string[];
        cap_drop: string[];
      };
    };
  };
  const oidc = parse(oidcRaw) as {
    services: { dashboard: { command: string[]; environment: Record<string, string> } };
  };

  const dashboard = base.services.dashboard;
  assert.equal(base.name, "vibeguard");
  assert.equal(dashboard.ports[0].startsWith("${VIBEGUARD_DASHBOARD_BIND:-127.0.0.1}"), true);
  assert.equal(dashboard.command.includes("--ingest-token-env"), true);
  assert.equal(dashboard.command.includes("VIBEGUARD_FINDINGS_INGEST_TOKEN"), true);
  assert.match(dashboard.environment.VIBEGUARD_DASHBOARD_TOKEN, /:\?/);
  assert.match(dashboard.environment.VIBEGUARD_FINDINGS_INGEST_TOKEN, /:\?/);
  assert.deepEqual(dashboard.volumes, ["vibeguard-data:/data"]);
  assert.match(dashboard.healthcheck.test.join(" "), /healthz/);
  assert.equal(dashboard.restart, "unless-stopped");
  assert.deepEqual(dashboard.security_opt, ["no-new-privileges:true"]);
  assert.deepEqual(dashboard.cap_drop, ["ALL"]);

  assert.equal(oidc.services.dashboard.command.includes("--secure-cookies"), true);
  assert.equal(oidc.services.dashboard.command.includes("--oidc-issuer-env"), true);
  assert.equal(oidc.services.dashboard.command.includes("--oidc-role"), true);
  assert.match(oidc.services.dashboard.environment.VIBEGUARD_PUBLIC_URL, /:\?/);
  assert.match(envExample, /VIBEGUARD_FINDINGS_INGEST_TOKEN=/);
  assert.match(ci, /docker compose -f deploy\/compose\.yaml config --quiet/);
});

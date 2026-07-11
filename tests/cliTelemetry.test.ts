import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);

test("CLI reports a false-positive dismissal without leaking ignore-rule details", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-cli-telemetry-"));
  const configPath = path.join(tempDir, "config.json");
  const ignoreRulesPath = path.join(tempDir, "ignore-rules.yml");
  await fs.writeFile(configPath, JSON.stringify({ telemetry: true }), "utf8");

  let body = "";
  const server = createServer((request, response) => {
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      response.writeHead(204).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");

  try {
    await execFileAsync(
      process.execPath,
      [
        path.resolve(process.cwd(), "out", "src", "cli.js"),
        "ignore-rules",
        "add-rule",
        "internal_rule_name",
        "--reason",
        "false_positive",
        "--config",
        configPath,
        "--ignore-rules",
        ignoreRulesPath,
        "--json"
      ],
      {
        env: {
          ...process.env,
          VIBEGUARD_TELEMETRY_ENDPOINT: `http://127.0.0.1:${address.port}/feedback`
        }
      }
    );
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }

  const event = JSON.parse(body) as Record<string, unknown>;
  const ignoreRules = await fs.readFile(ignoreRulesPath, "utf8");
  assert.deepEqual(event, {
    schemaVersion: 1,
    event: "false_positive_dismissal",
    source: "cli",
    scope: "global",
    ruleFingerprint: "c21925edc1cf5c90d55fe58d"
  });
  assert.equal(body.includes("internal_rule_name"), false);
  assert.match(ignoreRules, /internal_rule_name/);
});

test("CLI saves an ignore rule even when telemetry configuration cannot be loaded", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-cli-telemetry-invalid-config-"));
  const configPath = path.join(tempDir, "invalid-config.json");
  const ignoreRulesPath = path.join(tempDir, "ignore-rules.yml");
  await fs.writeFile(configPath, "{not json", "utf8");

  await execFileAsync(process.execPath, [
    path.resolve(process.cwd(), "out", "src", "cli.js"),
    "ignore-rules",
    "add-rule",
    "rule_with_invalid_config",
    "--reason",
    "false_positive",
    "--config",
    configPath,
    "--ignore-rules",
    ignoreRulesPath
  ]);

  const ignoreRules = await fs.readFile(ignoreRulesPath, "utf8");
  assert.match(ignoreRules, /rule_with_invalid_config/);
});

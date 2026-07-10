import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ensureConfigFile,
  loadConfig,
  parseConfig,
  resolveConfigCustomRulePaths,
  resolveConfigRelativePath,
  updateIgnoredFinding,
  updateLlmApiKeyStored
} from "../src/config";

test("parses partial config and preserves defaults", () => {
  const config = parseConfig(
    JSON.stringify({
      detection_layers: {
        l3: true
      },
      package_verification: "off",
      dedup_with_existing_tools: false,
      custom_rules: ["./rules/company.yml"],
      package_cache: {
        languages: ["npm", "maven"],
        update_interval: "weekly"
      }
    }),
    "config.json"
  );

  assert.equal(config.enabled, true);
  assert.equal(config.detection_layers.l1, true);
  assert.equal(config.detection_layers.l2, true);
  assert.equal(config.detection_layers.l3, true);
  assert.equal(config.package_verification, "off");
  assert.equal(config.dedup_with_existing_tools, false);
  assert.deepEqual(config.custom_rules, ["./rules/company.yml"]);
  assert.deepEqual(config.package_cache.languages, ["npm", "maven"]);
  assert.equal(config.package_cache.update_interval, "weekly");
  assert.equal(config.package_cache.lightweight_mode, true);
});

test("parses UTF-8 BOM config files", () => {
  const config = parseConfig(`\uFEFF{"enabled":false}`);

  assert.equal(config.enabled, false);
});

test("rejects invalid config field types and enums", () => {
  assert.throws(
    () => parseConfig(JSON.stringify({ detection_layers: { l2: "yes" } }), "bad.json"),
    /detection_layers\.l2 must be boolean/
  );
  assert.throws(
    () => parseConfig(JSON.stringify({ package_verification: "network" }), "bad.json"),
    /package_verification must be one of/
  );
  assert.throws(
    () => parseConfig(JSON.stringify({ llm_api_key: "secret" }), "bad.json"),
    /llm_api_key must be null/
  );
});

test("loads defaults when config file is missing", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-config-missing-"));
  const loaded = await loadConfig(path.join(tempDir, "missing.json"));

  assert.equal(loaded.exists, false);
  assert.equal(loaded.config.package_verification, "seed");
  assert.equal(loaded.config.detection_layers.l2, true);
});

test("creates default config files", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-config-"));
  const configPath = path.join(tempDir, "config.json");

  const first = await ensureConfigFile(configPath);
  const second = await ensureConfigFile(configPath);
  const loaded = await loadConfig(configPath);

  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(loaded.exists, true);
  assert.equal(loaded.config.package_verification, "seed");
});

test("updates ignored finding ids in config files", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-config-ignore-"));
  const configPath = path.join(tempDir, "config.json");

  const added = await updateIgnoredFinding("vg_123", "add", configPath);
  const addedAgain = await updateIgnoredFinding("vg_123", "add", configPath);
  const removed = await updateIgnoredFinding("vg_123", "remove", configPath);

  assert.deepEqual(added.ignoredFindings, ["vg_123"]);
  assert.deepEqual(addedAgain.ignoredFindings, ["vg_123"]);
  assert.deepEqual(removed.ignoredFindings, []);
});

test("updates llm api key stored marker without writing plaintext keys", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-config-llm-"));
  const configPath = path.join(tempDir, "config.json");

  const stored = await updateLlmApiKeyStored(true, configPath, "openai");
  const loadedStored = await loadConfig(configPath);
  const removed = await updateLlmApiKeyStored(false, configPath, "openai");
  const raw = await fs.readFile(configPath, "utf8");

  assert.equal(stored.llmApiKeyStored, true);
  assert.equal(loadedStored.config.llm_provider, "openai");
  assert.equal(loadedStored.config.llm_api_key_stored, true);
  assert.equal(loadedStored.config.llm_api_key, null);
  assert.equal(removed.llmApiKeyStored, false);
  assert.match(raw, /"llm_api_key": null/);
});

test("resolves config-relative custom rule paths", () => {
  const configPath = path.join(os.tmpdir(), "vibeguard-home", ".vibeguard", "config.json");
  const config = parseConfig(JSON.stringify({ custom_rules: ["./rules.yml"] }));
  const resolved = resolveConfigCustomRulePaths(config, configPath);

  assert.deepEqual(resolved, [path.resolve(path.dirname(configPath), "rules.yml")]);
  assert.equal(resolveConfigRelativePath(path.join(os.tmpdir(), "absolute.yml"), configPath), path.join(os.tmpdir(), "absolute.yml"));
});

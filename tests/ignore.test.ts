import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { appendIgnoreRule, normalizeIgnoreReason, parseIgnoreRules, scopedIgnoreReason } from "../src/ignore";

test("normalizes standard ignore reasons and preserves custom reasons", () => {
  assert.equal(normalizeIgnoreReason("false_positive"), "False positive");
  assert.equal(normalizeIgnoreReason("Not an issue"), "Not an issue");
  assert.equal(normalizeIgnoreReason("internal-package"), "Internal package");
  assert.equal(normalizeIgnoreReason("accepted for generated fixture"), "accepted for generated fixture");
  assert.equal(normalizeIgnoreReason(undefined, "fallback reason"), "fallback reason");
});

test("adds scope context to ignore reasons", () => {
  assert.equal(scopedIgnoreReason("false_positive", "line"), "False positive (line ignore)");
  assert.equal(scopedIgnoreReason("internal_package", "package"), "Internal package (package ignore)");
  assert.equal(scopedIgnoreReason(undefined, "global"), undefined);
});

test("appends ignore rules with normalized reasons", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-ignore-"));
  const filePath = path.join(tempDir, "ignore-rules.yml");
  await appendIgnoreRule(
    {
      rule: "insecure_config_debug_true",
      path: "**/test_*",
      reason: scopedIgnoreReason("not_issue", "file")
    },
    filePath
  );

  const parsed = parseIgnoreRules(await fs.readFile(filePath, "utf8"));

  assert.equal(parsed.ignore.length, 1);
  assert.equal(parsed.ignore[0].rule, "insecure_config_debug_true");
  assert.equal(parsed.ignore[0].reason, "Not an issue (file ignore)");
});

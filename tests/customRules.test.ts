import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { detectCustomRules, loadCustomRules, parseCustomRules } from "../src/customRules";
import { scanSourceFile } from "../src/scanner";

const customRulesYaml = `
rules:
  - id: company_public_s3_acl
    pattern: "public-read"
    severity: high
    type: insecure_config
    layer: L1
    languages: ["json"]
    message: "S3 bucket ACL is public."
    suggestion: "Use private ACLs and bucket policies."
`;

test("parses custom YAML rules", () => {
  const parsed = parseCustomRules(customRulesYaml, "rules.yml");

  assert.equal(parsed.rules.length, 1);
  assert.equal(parsed.rules[0].id, "company_public_s3_acl");
  assert.equal(parsed.rules[0].severity, "high");
  assert.equal(parsed.rules[0].type, "insecure_config");
  assert.deepEqual(parsed.rules[0].languages, ["json"]);
});

test("detects custom rule findings with language filters", () => {
  const rules = parseCustomRules(customRulesYaml).rules;
  const findings = detectCustomRules(
    {
      filePath: "bucket.json",
      languageId: "json",
      text: `{ "acl": "public-read" }`
    },
    rules,
    1
  );
  const skipped = detectCustomRules(
    {
      filePath: "bucket.ts",
      languageId: "typescript",
      text: `const acl = "public-read";`
    },
    rules,
    1
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].detection_rule, "custom.company_public_s3_acl");
  assert.equal(findings[0].detection_layer, "L1");
  assert.equal(findings[0].message, "S3 bucket ACL is public.");
  assert.equal(skipped.length, 0);
});

test("runs custom rules through the scanner pipeline", async () => {
  const rules = parseCustomRules(customRulesYaml).rules;
  const result = await scanSourceFile(
    {
      filePath: "bucket.json",
      languageId: "json",
      text: `{ "acl": "public-read" }`
    },
    {
      packageVerification: "off",
      includeSast: false,
      customRules: rules,
      now: 1
    }
  );

  assert.equal(result.findings.some((finding) => finding.detection_rule === "custom.company_public_s3_acl"), true);
});

test("loads custom rule files from disk", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-custom-rules-"));
  const filePath = path.join(tempDir, "rules.yml");
  await fs.writeFile(filePath, customRulesYaml, "utf8");

  const rules = await loadCustomRules([filePath]);

  assert.equal(rules.length, 1);
  assert.equal(rules[0].id, "company_public_s3_acl");
});

test("rejects invalid custom rule regexes", () => {
  assert.throws(
    () =>
      parseCustomRules(`
rules:
  - id: broken
    pattern: "["
    severity: high
    type: other
    message: "Broken"
`),
    /Invalid regular expression/
  );
});

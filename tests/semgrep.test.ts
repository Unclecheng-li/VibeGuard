import assert from "node:assert/strict";
import test from "node:test";
import { parse } from "yaml";
import { formatSemgrepRules, semgrepExportRules } from "../src/semgrep";

test("exports VibeGuard rules as Semgrep YAML", () => {
  const parsed = parse(formatSemgrepRules()) as {
    rules: Array<{
      id: string;
      languages: string[];
      severity: string;
      message: string;
      "pattern-regex": string;
      metadata: {
        technology: string[];
        vibeguard: {
          rule_id: string;
          detection_layer: string;
          finding_type: string;
          severity: string;
        };
      };
    }>;
  };

  assert.equal(parsed.rules.length, semgrepExportRules.length);
  assert.equal(new Set(parsed.rules.map((rule) => rule.id)).size, parsed.rules.length);
  assert.equal(parsed.rules.some((rule) => rule.id === "vibeguard.sast_sql_template_interpolation"), true);
  assert.equal(parsed.rules.some((rule) => rule.id === "vibeguard.ai_pattern_default_password"), true);

  const sqlRule = parsed.rules.find((rule) => rule.id === "vibeguard.sast_sql_template_interpolation");
  assert.equal(sqlRule?.severity, "ERROR");
  assert.deepEqual(sqlRule?.languages, ["javascript", "typescript"]);
  assert.equal(sqlRule?.metadata.vibeguard.rule_id, "sast_sql_template_interpolation");
  assert.equal(sqlRule?.metadata.vibeguard.detection_layer, "L2");
  assert.equal(sqlRule?.metadata.vibeguard.finding_type, "sql_injection");
  assert.match(sqlRule?.["pattern-regex"] ?? "", /SELECT/);
});

test("allows custom Semgrep rule id prefixes", () => {
  const parsed = parse(formatSemgrepRules({ rulePrefix: "company.vibeguard" })) as {
    rules: Array<{ id: string }>;
  };

  assert.equal(parsed.rules.every((rule) => rule.id.startsWith("company.vibeguard.")), true);
});

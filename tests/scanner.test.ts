import assert from "node:assert/strict";
import test from "node:test";
import { parseIgnoreRules } from "../src/ignore";
import { scanSourceFile } from "../src/scanner";

test("detects known hallucinated npm packages from the seed catalog", async () => {
  const result = await scanSourceFile(
    {
      filePath: "demo.ts",
      languageId: "typescript",
      text: `import AutoSizer from "react-virtualized-auto-sizer";`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, "hallucinated_package");
  assert.match(result.findings[0].suggestion ?? "", /react-virtualized/);
  assert.equal(result.findings[0].fix?.edits[0].newText, "react-virtualized");
});

test("detects hardcoded secrets and redacts evidence", async () => {
  const result = await scanSourceFile(
    {
      filePath: "settings.py",
      languageId: "python",
      text: `OPENAI_API_KEY = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings[0].type, "hardcoded_secret");
  assert.equal(result.findings[0].severity, "critical");
  assert.doesNotMatch(result.findings[0].evidence, /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
});

test("ignores environment-backed secret assignments", async () => {
  const result = await scanSourceFile(
    {
      filePath: "settings.py",
      languageId: "python",
      text: `API_KEY = os.getenv("API_KEY")`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 0);
});

test("detects unsafe config and common AI password patterns", async () => {
  const result = await scanSourceFile(
    {
      filePath: "app.py",
      languageId: "python",
      text: `DEBUG = True\npassword = "admin"`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.some((finding) => finding.detection_rule === "insecure_config_debug_true"), true);
  assert.equal(result.findings.some((finding) => finding.detection_rule === "ai_pattern_default_password"), true);
});

test("detects lightweight L2 SQL injection patterns", async () => {
  const result = await scanSourceFile(
    {
      filePath: "db.ts",
      languageId: "typescript",
      text: "const query = `SELECT * FROM users WHERE id = ${req.query.id}`;"
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  assert.equal(result.findings.some((finding) => finding.type === "sql_injection"), true);
});

test("marks findings dismissed when rule and file scope match ignore-rules.yml", async () => {
  const ignoreRules = parseIgnoreRules(`
ignore:
  - rule: "insecure_config_debug_true"
    scope: "file:**/test_*"
    reason: "test files may enable debug"
`);

  const result = await scanSourceFile(
    {
      filePath: "/repo/test_app.py",
      languageId: "python",
      text: "DEBUG = True"
    },
    {
      packageVerification: "off",
      includeSast: false,
      ignoreRules,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].dismissed, true);
  assert.equal(result.findings[0].dismissed_reason, "test files may enable debug");
});

test("supports path rules with finding type names", async () => {
  const ignoreRules = parseIgnoreRules(`
ignore:
  - path: "**/migrations/**"
    rules: ["sql_injection"]
`);

  const result = await scanSourceFile(
    {
      filePath: "/repo/app/migrations/001.ts",
      languageId: "typescript",
      text: "const query = `SELECT * FROM users WHERE id = ${req.query.id}`;"
    },
    {
      packageVerification: "off",
      includeSast: true,
      ignoreRules,
      now: 1
    }
  );

  assert.equal(result.findings.some((finding) => finding.type === "sql_injection" && finding.dismissed), true);
});

test("supports package ignore rules for private packages", async () => {
  const ignoreRules = parseIgnoreRules(`
ignore:
  - package: "react-virtualized-auto-sizer"
    registry: "npm"
    reason: "private registry package"
`);

  const result = await scanSourceFile(
    {
      filePath: "demo.ts",
      languageId: "typescript",
      text: `import AutoSizer from "react-virtualized-auto-sizer";`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      ignoreRules,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].dismissed, true);
  assert.equal(result.findings[0].dismissed_reason, "private registry package");
});

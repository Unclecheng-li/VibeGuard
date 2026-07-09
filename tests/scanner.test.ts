import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseIgnoreRules } from "../src/ignore";
import { JsonPackageNameIndex } from "../src/package/cache";
import { parsePackageNameList } from "../src/package/importer";
import { PackageVerifier } from "../src/package/packageVerifier";
import { SqlitePackageCache, SqlitePackageNameIndex, isSqliteAvailable } from "../src/package/sqliteStore";
import { fetchPackageNames, parsePypiSimple } from "../src/package/sync";
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

test("detects hallucinated Cargo packages from Cargo.toml", async () => {
  const result = await scanSourceFile(
    {
      filePath: "Cargo.toml",
      languageId: "toml",
      text: `[dependencies]
serde = "1"
tokio-secure-auth = "0.1"
`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detection_rule, "hallucinated_package_cargo");
  assert.match(result.findings[0].suggestion ?? "", /tokio/);
});

test("detects hallucinated Go modules from go.mod", async () => {
  const result = await scanSourceFile(
    {
      filePath: "go.mod",
      languageId: "go.mod",
      text: `module example.com/demo

require (
  github.com/gin-gonic/gin v1.9.1
  github.com/gin-gonic/secure-gin v0.1.0
)
`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detection_rule, "hallucinated_package_gomod");
  assert.match(result.findings[0].suggestion ?? "", /github\.com\/gin-gonic\/gin/);
});

test("detects hallucinated Maven packages from pom.xml", async () => {
  const result = await scanSourceFile(
    {
      filePath: "pom.xml",
      languageId: "xml",
      text: `<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.3.0</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-secure-api</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detection_rule, "hallucinated_package_maven");
  assert.equal(result.findings[0].fix, undefined);
  assert.match(result.findings[0].suggestion ?? "", /spring-boot-starter-security/);
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

test("adds code fixes for high-confidence insecure config findings", async () => {
  const result = await scanSourceFile(
    {
      filePath: "app.py",
      languageId: "python",
      text: "DEBUG = True"
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const debugFinding = result.findings.find((finding) => finding.detection_rule === "insecure_config_debug_true");
  assert.equal(debugFinding?.fix?.edits[0].newText, "DEBUG = False");
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

test("does not run L3 semantic checks unless enabled", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `
app.post("/api/admin/users", (req, res) => {
  const name = req.body.name;
  res.json({ ok: true, name });
});
`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.some((finding) => finding.detection_layer === "L3"), false);
});

test("detects L3 endpoint security gaps when enabled", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `
app.post("/api/admin/users", (req, res) => {
  const name = req.body.name;
  res.json({ ok: true, name });
});
`
    },
    {
      packageVerification: "off",
      includeSast: false,
      includeL3: true,
      now: 1
    }
  );

  const ruleIds = result.findings.map((finding) => finding.detection_rule);
  assert.equal(result.findings.every((finding) => finding.detection_layer === "L3"), true);
  assert.equal(ruleIds.includes("l3_missing_authentication"), true);
  assert.equal(ruleIds.includes("l3_missing_rate_limiting"), true);
  assert.equal(ruleIds.includes("l3_missing_input_validation"), true);
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

test("parses package name import formats", () => {
  assert.deepEqual(parsePackageNameList("express\nreact\n# comment\n").names, ["express", "react"]);
  assert.deepEqual(parsePackageNameList('["fastapi", "django"]').names, ["fastapi", "django"]);
  assert.deepEqual(parsePackageNameList('{"rows":[{"id":"lodash"},{"key":"axios"}]}').names, ["lodash", "axios"]);
});

test("uses full local package index to detect missing packages", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-index-"));
  const index = new JsonPackageNameIndex(path.join(tempDir, "package-index.json"));
  await index.importPackageNames("npm", ["react", "express"], "full");

  const result = await scanSourceFile(
    {
      filePath: "demo.ts",
      languageId: "typescript",
      text: `import thing from "definitely-not-real-package";`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      packageVerifier: new PackageVerifier({ packageIndex: index }),
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, "hallucinated_package");
  assert.match(result.findings[0].suggestion ?? "", /full local package index/);
});

test("uses partial local package index as an existence cache", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-index-"));
  const index = new JsonPackageNameIndex(path.join(tempDir, "package-index.json"));
  await index.importPackageNames("npm", ["my-private-package"], "partial");

  const result = await scanSourceFile(
    {
      filePath: "demo.ts",
      languageId: "typescript",
      text: `import thing from "my-private-package";`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      packageVerifier: new PackageVerifier({ packageIndex: index }),
      now: 1
    }
  );

  assert.equal(result.findings.length, 0);
});

test("stores package resolution cache entries in SQLite when available", async (context) => {
  if (!isSqliteAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-sqlite-"));
  const cache = new SqlitePackageCache(path.join(tempDir, "packages.db"));
  await cache.set({
    registry: "npm",
    packageName: "missing-package",
    exists: false,
    source: "remote",
    lastVerified: 123,
    similarPackages: ["real-package"],
    message: "Registry returned 404."
  });

  const cached = await cache.get("npm", "missing-package");
  assert.equal(cached?.exists, false);
  assert.equal(cached?.source, "remote");
  assert.deepEqual(cached?.similarPackages, ["real-package"]);
  cache.close();
});

test("uses SQLite full local package index to detect missing packages when available", async (context) => {
  if (!isSqliteAvailable()) {
    context.skip("node:sqlite is not available in this runtime");
    return;
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-sqlite-"));
  const index = new SqlitePackageNameIndex(path.join(tempDir, "packages.db"));
  await index.importPackageNames("npm", ["react", "express"], "full");

  const result = await scanSourceFile(
    {
      filePath: "demo.ts",
      languageId: "typescript",
      text: `import thing from "definitely-not-real-package";`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      packageVerifier: new PackageVerifier({ packageIndex: index }),
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, "hallucinated_package");
  index.close();
});

test("fetches npm package names from _all_docs responses with truncation metadata", async () => {
  const result = await fetchPackageNames({
    registry: "npm",
    sourceUrl: "https://example.test/_all_docs",
    limit: 2,
    fetchImpl: async (url) =>
      ({
        ok: true,
        status: 200,
        url: String(url),
        text: async () =>
          JSON.stringify({
            total_rows: 3,
            rows: [{ id: "react" }, { id: "express" }, { id: "_design/app" }]
          })
      }) as Response
  });

  assert.deepEqual(result.names, ["react", "express"]);
  assert.equal(result.truncated, true);
  assert.match(result.sourceUrl, /limit=2/);
});

test("parses PyPI simple HTML package names", () => {
  const parsed = parsePypiSimple(`
    <!doctype html>
    <a href="/simple/fastapi/">fastapi</a>
    <a href="/simple/django/">django</a>
    <a href="/simple/black/">black&amp;white</a>
  `);

  assert.deepEqual(parsed.names, ["fastapi", "django", "black&white"]);
  assert.equal(parsed.format, "pypi-simple");
});

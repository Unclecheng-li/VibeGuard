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
import {
  fetchPackageNames,
  parseCargoCrates,
  parseGoModuleIndex,
  parseMavenSearch,
  parsePypiSimple
} from "../src/package/sync";
import { scanSourceFile } from "../src/scanner";
import type { Finding } from "../src/types";

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

test("records scan performance timings and budget warnings", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `app.get("/health", (_req, res) => res.json({ ok: true }));`
    },
    {
      packageVerification: "off",
      includeSast: false,
      includeL3: true,
      performanceBudgets: {
        l3Ms: 1
      },
      l3Analyzer: {
        analyze: async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return [];
        }
      },
      now: 1
    }
  );

  assert.equal(result.performance.file, "routes.ts");
  assert.equal(result.performance.lineCount, 1);
  assert.equal(result.performance.timings.totalMs >= result.performance.timings.l3Ms, true);
  assert.equal(result.performance.budgetExceeded, true);
  assert.equal(result.performance.budgets.some((check) => check.layer === "L3" && check.exceeded), true);
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
  const text = `OPENAI_API_KEY = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`;
  const result = await scanSourceFile(
    {
      filePath: "settings.py",
      languageId: "python",
      text
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
  assert.equal(
    applyAllFixes(text, result.findings[0]),
    `import os\nOPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")`
  );
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

test("detects contextual high-entropy secret assignments", async () => {
  const secret = "mF9qT2vL8zP4xR7cN1bY6kD3sH0aW5eJ";
  const text = `const webhookSecret = "${secret}";`;
  const result = await scanSourceFile(
    {
      filePath: "webhooks.ts",
      languageId: "typescript",
      text
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "hardcoded_secret_high_entropy_assignment");
  assert.equal(finding?.type, "hardcoded_secret");
  assert.equal(finding?.severity, "critical");
  assert.doesNotMatch(finding?.evidence ?? "", new RegExp(secret));
  assert.equal(applyAllFixes(text, finding), `const webhookSecret = process.env.WEBHOOK_SECRET ?? "";`);
});

test("detects high-entropy bearer tokens in authorization headers", async () => {
  const token = "A7kL9pQ2rT8xZ4mN6vC1bY5dF3hS0wE";
  const result = await scanSourceFile(
    {
      filePath: "client.ts",
      languageId: "typescript",
      text: `const headers = { Authorization: "Bearer ${token}" };`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "hardcoded_secret_high_entropy_assignment");
  assert.equal(finding?.type, "hardcoded_secret");
  assert.match(finding?.evidence ?? "", /Authorization = /);
  assert.doesNotMatch(finding?.evidence ?? "", new RegExp(token));
  assert.equal(finding?.fix, undefined);
});

test("ignores high-entropy-looking hashes, fixtures, and placeholders", async () => {
  const result = await scanSourceFile(
    {
      filePath: "fixtures.ts",
      languageId: "typescript",
      text: `
const checksum = "5f4dcc3b5aa765d61d8327deb882cf99";
const fixture = "mF9qT2vL8zP4xR7cN1bY6kD3sH0aW5eJ";
const exampleToken = "test-token";
`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 0);
});

test("detects additional provider token formats", async () => {
  const text = `const stripeKey = "sk_live_1234567890abcdefghijkl";`;
  const result = await scanSourceFile(
    {
      filePath: "payments.ts",
      languageId: "typescript",
      text
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "hardcoded_secret_stripe_key");
  assert.ok(finding);
  assert.equal(applyAllFixes(text, finding), `const stripeKey = process.env.STRIPE_KEY ?? "";`);
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

test("detects expanded JavaScript AI security anti-patterns", async () => {
  const result = await scanSourceFile(
    {
      filePath: "auth.ts",
      languageId: "typescript",
      text: `
app.use(cors({ origin: "*", credentials: true }));
jwt.verify(token, publicKey, { algorithms: ["none"] });
const claims = jwt.decode(token);
jwt.verify(token, secret, { ignoreExpiration: true });
await bcrypt.hash(password, 1);
if (user.password === password) login();
const digest = crypto.createHash("md5").update(password).digest("hex");
app.use(session({ secret: "keyboard cat" }));
const resetToken = Math.random().toString(36);
s3.putObject({ Bucket, Key, ACL: "public-read" });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const ruleIds = new Set(result.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("ai_pattern_cors_credentials_wildcard"), true);
  assert.equal(ruleIds.has("ai_pattern_jwt_none_algorithm"), true);
  assert.equal(ruleIds.has("ai_pattern_jwt_decode_without_verify"), true);
  assert.equal(ruleIds.has("ai_pattern_jwt_ignore_expiration"), true);
  assert.equal(ruleIds.has("ai_pattern_bcrypt_low_rounds"), true);
  assert.equal(ruleIds.has("ai_pattern_plaintext_password_compare"), true);
  assert.equal(ruleIds.has("ai_pattern_weak_password_hash"), true);
  assert.equal(ruleIds.has("ai_pattern_session_secret_placeholder"), true);
  assert.equal(ruleIds.has("ai_pattern_math_random_token"), true);
  assert.equal(ruleIds.has("ai_pattern_s3_public_read_acl"), true);
  assert.equal(ruleIds.has("ai_pattern_tls_verification_disabled"), true);
});

test("detects expanded Python AI security anti-patterns", async () => {
  const result = await scanSourceFile(
    {
      filePath: "app.py",
      languageId: "python",
      text: `
requests.get(url, verify=False)
app.config["SECRET_KEY"] = "dev"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
`
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const ruleIds = new Set(result.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("ai_pattern_requests_verify_false"), true);
  assert.equal(ruleIds.has("ai_pattern_flask_secret_key_placeholder"), true);
  assert.equal(ruleIds.has("ai_pattern_fastapi_cors_credentials_wildcard"), true);
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

test("adds code fixes for unsafe yaml.load config findings", async () => {
  const result = await scanSourceFile(
    {
      filePath: "loader.py",
      languageId: "python",
      text: "data = yaml.load(payload)"
    },
    {
      packageVerification: "off",
      includeSast: false,
      now: 1
    }
  );

  const yamlFinding = result.findings.find((finding) => finding.detection_rule === "insecure_config_yaml_load_without_loader");
  assert.equal(yamlFinding?.fix?.edits[0].newText, "yaml.safe_load(payload)");
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

test("adds code fixes for L2 innerHTML findings", async () => {
  const result = await scanSourceFile(
    {
      filePath: "view.ts",
      languageId: "typescript",
      text: "element.innerHTML = req.query.name;"
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "sast_xss_inner_html");
  assert.equal(finding?.fix?.edits[0].newText, ".textContent = req.query.name");
  assert.equal(applyFirstFix("element.innerHTML = req.query.name;", finding), "element.textContent = req.query.name;");
});

test("adds code fixes for L2 unsafe yaml.load findings", async () => {
  const result = await scanSourceFile(
    {
      filePath: "loader.py",
      languageId: "python",
      text: "data = yaml.load(request.data)"
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "sast_insecure_deserialization_yaml");
  assert.equal(finding?.fix?.edits[0].newText, "yaml.safe_load(request.data");
  assert.equal(applyFirstFix("data = yaml.load(request.data)", finding), "data = yaml.safe_load(request.data)");
});

test("detects lightweight L2 open redirect patterns", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `app.get("/next", (req, res) => res.redirect(req.query.next));`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.type === "open_redirect");
  assert.equal(finding?.detection_rule, "sast_open_redirect_user_input");
  assert.equal(finding?.severity, "medium");
});

test("detects lightweight L2 information leakage patterns", async () => {
  const result = await scanSourceFile(
    {
      filePath: "errors.ts",
      languageId: "typescript",
      text: `app.get("/debug", (req, res) => {
  try {
    throw new Error("boom");
  } catch (err) {
    res.status(500).send(err.stack);
  }
});`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.type === "information_leakage");
  assert.equal(finding?.detection_rule, "sast_information_leakage_error_details");
  assert.equal(finding?.severity, "low");
});

test("deduplicates L2 findings with nearby existing SAST annotations", async () => {
  const result = await scanSourceFile(
    {
      filePath: "db.ts",
      languageId: "typescript",
      text: `// nosemgrep: sast_sql_template_interpolation
const query = \`SELECT * FROM users WHERE id = \${req.query.id}\`;`
    },
    {
      packageVerification: "off",
      includeSast: true,
      dedupWithExistingTools: true,
      now: 1
    }
  );

  const sqlFinding = result.findings.find((finding) => finding.type === "sql_injection");
  assert.equal(sqlFinding?.dismissed, true);
  assert.match(sqlFinding?.dismissed_reason ?? "", /existing SAST annotation/);
});

test("keeps duplicate L2 findings active when existing-tool dedup is disabled", async () => {
  const result = await scanSourceFile(
    {
      filePath: "db.ts",
      languageId: "typescript",
      text: `// sonarjs/no-sql-injection
const query = \`SELECT * FROM users WHERE id = \${req.query.id}\`;`
    },
    {
      packageVerification: "off",
      includeSast: true,
      dedupWithExistingTools: false,
      now: 1
    }
  );

  const sqlFinding = result.findings.find((finding) => finding.type === "sql_injection");
  assert.equal(sqlFinding?.dismissed, false);
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

test("marks findings dismissed when their ids are configured", async () => {
  const source = {
    filePath: "app.py",
    languageId: "python",
    text: "DEBUG = True"
  };
  const initial = await scanSourceFile(source, {
    packageVerification: "off",
    includeSast: false,
    now: 1
  });
  const findingId = initial.findings[0].id;

  const result = await scanSourceFile(source, {
    packageVerification: "off",
    includeSast: false,
    ignoredFindingIds: [findingId],
    now: 1
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, findingId);
  assert.equal(result.findings[0].dismissed, true);
  assert.equal(result.findings[0].dismissed_reason, "Matched config.ignored_findings");
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

test("uses local package index suggestions for close package names", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vibeguard-index-suggest-"));
  const index = new JsonPackageNameIndex(path.join(tempDir, "package-index.json"));
  await index.importPackageNames("npm", ["rxjs", "react", "express"], "full");

  const result = await scanSourceFile(
    {
      filePath: "demo.ts",
      languageId: "typescript",
      text: `import { of } from "rxjss";`
    },
    {
      packageVerification: "seed",
      includeSast: false,
      packageVerifier: new PackageVerifier({ packageIndex: index }),
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.match(result.findings[0].suggestion ?? "", /"rxjs"/);
  assert.equal(result.findings[0].fix?.edits[0].newText, "rxjs");
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
  assert.deepEqual(await index.suggest("npm", "exress"), ["express"]);
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

test("fetches Maven package names from Solr search responses", async () => {
  const result = await fetchPackageNames({
    registry: "maven",
    sourceUrl: "https://example.test/solrsearch/select?q=*:*&wt=json",
    limit: 1,
    fetchImpl: async (url) =>
      ({
        ok: true,
        status: 200,
        url: String(url),
        text: async () =>
          JSON.stringify({
            response: {
              numFound: 2,
              docs: [
                { g: "org.springframework.boot", a: "spring-boot-starter-web" },
                { g: "org.springframework.boot", a: "spring-boot-starter-security" }
              ]
            }
          })
      }) as Response
  });

  assert.deepEqual(result.names, ["org.springframework.boot:spring-boot-starter-web"]);
  assert.equal(result.truncated, true);
  assert.equal(result.format, "maven-search");
  assert.match(result.sourceUrl, /rows=1/);
});

test("paginates Cargo package sync responses until the requested limit", async () => {
  const requestedUrls: string[] = [];
  const result = await fetchPackageNames({
    registry: "cargo",
    sourceUrl: "https://example.test/api/v1/crates",
    limit: 3,
    fetchImpl: async (url) => {
      requestedUrls.push(String(url));
      const page = new URL(String(url)).searchParams.get("page");
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            crates: page === "1" ? [{ id: "serde" }, { id: "tokio" }] : [{ id: "axum" }, { id: "clap" }],
            meta: { total: 4 }
          })
      } as Response;
    }
  });

  assert.deepEqual(result.names, ["serde", "tokio", "axum"]);
  assert.equal(result.pagesFetched, 2);
  assert.equal(result.truncated, true);
  assert.match(requestedUrls[0], /page=1/);
  assert.match(requestedUrls[0], /per_page=3/);
  assert.match(requestedUrls[1], /page=2/);
});

test("paginates Maven package sync responses until numFound is reached", async () => {
  const requestedUrls: string[] = [];
  const result = await fetchPackageNames({
    registry: "maven",
    sourceUrl: "https://example.test/solrsearch/select?q=*:*&wt=json",
    fetchImpl: async (url) => {
      requestedUrls.push(String(url));
      const start = new URL(String(url)).searchParams.get("start");
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            response: {
              numFound: 3,
              docs:
                start === "0"
                  ? [
                      { g: "junit", a: "junit" },
                      { g: "org.slf4j", a: "slf4j-api" }
                    ]
                  : [{ g: "com.fasterxml.jackson.core", a: "jackson-databind" }]
            }
          })
      } as Response;
    }
  });

  assert.deepEqual(result.names, [
    "junit:junit",
    "org.slf4j:slf4j-api",
    "com.fasterxml.jackson.core:jackson-databind"
  ]);
  assert.equal(result.pagesFetched, 2);
  assert.equal(result.truncated, false);
  assert.match(requestedUrls[0], /start=0/);
  assert.match(requestedUrls[0], /rows=100/);
  assert.match(requestedUrls[1], /start=100/);
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

test("parses Cargo crates API package names", () => {
  const parsed = parseCargoCrates(
    JSON.stringify({
      crates: [{ id: "serde" }, { name: "tokio" }, { id: "serde" }],
      meta: { total: 2 }
    })
  );

  assert.deepEqual(parsed.names, ["serde", "tokio", "serde"]);
  assert.equal(parsed.totalAvailable, 2);
  assert.equal(parsed.format, "cargo-crates");
});

test("parses Go module index package names", () => {
  const parsed = parseGoModuleIndex(`
{"Path":"github.com/gin-gonic/gin","Version":"v1.10.0"}
not-json
{"Path":"golang.org/x/net","Version":"v0.1.0"}
`);

  assert.deepEqual(parsed.names, ["github.com/gin-gonic/gin", "golang.org/x/net"]);
  assert.equal(parsed.format, "gomod-index");
});

test("parses Maven search package coordinates", () => {
  const parsed = parseMavenSearch(
    JSON.stringify({
      response: {
        numFound: 2,
        docs: [{ g: "junit", a: "junit" }, { id: "org.slf4j:slf4j-api" }]
      }
    })
  );

  assert.deepEqual(parsed.names, ["junit:junit", "org.slf4j:slf4j-api"]);
  assert.equal(parsed.totalAvailable, 2);
  assert.equal(parsed.format, "maven-search");
});

function applyFirstFix(text: string, finding: Finding | undefined): string {
  const edit = finding?.fix?.edits[0];
  assert.ok(edit);
  const start = offsetAt(text, edit.startLine, edit.startColumn);
  const end = offsetAt(text, edit.endLine, edit.endColumn);
  return `${text.slice(0, start)}${edit.newText}${text.slice(end)}`;
}

function applyAllFixes(text: string, finding: Finding | undefined): string {
  const edits = finding?.fix?.edits;
  assert.ok(edits);
  return [...edits]
    .map((edit) => ({
      ...edit,
      start: offsetAt(text, edit.startLine, edit.startColumn),
      end: offsetAt(text, edit.endLine, edit.endColumn)
    }))
    .sort((a, b) => b.start - a.start)
    .reduce((current, edit) => `${current.slice(0, edit.start)}${edit.newText}${current.slice(edit.end)}`, text);
}

function offsetAt(text: string, line: number, column: number): number {
  let currentLine = 1;
  let currentColumn = 1;
  for (let index = 0; index < text.length; index += 1) {
    if (currentLine === line && currentColumn === column) {
      return index;
    }
    if (text[index] === "\n") {
      currentLine += 1;
      currentColumn = 1;
    } else {
      currentColumn += 1;
    }
  }
  return text.length;
}

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseIgnoreRules } from "../src/ignore";
import { JsonPackageNameIndex, type PackageCacheStore } from "../src/package/cache";
import { parsePackageNameList } from "../src/package/importer";
import { PackageVerifier } from "../src/package/packageVerifier";
import { parsePackageReferences } from "../src/package/packageParser";
import { SqlitePackageCache, SqlitePackageNameIndex, isSqliteAvailable } from "../src/package/sqliteStore";
import { aiPatternRules } from "../src/rules/aiPatterns";
import { detectAstSast } from "../src/rules/astSast";
import {
  fetchPackageNames,
  parseCargoCrates,
  parseGoModuleIndex,
  parseMavenSearch,
  parsePypiSimple
} from "../src/package/sync";
import { scanSourceFile } from "../src/scanner";
import type { Finding, PackageReference } from "../src/types";

test("releases Tree-sitter parse state after an incomplete edit before the next scan", async () => {
  const incomplete = await detectAstSast("app.get(\"/orders\", (req, res) => {", "orders.ts", "typescript");
  const next = await detectAstSast("const query = `SELECT * FROM orders WHERE id = ${req.query.id}`;", "orders.ts", "typescript");

  assert.deepEqual([...incomplete.handledRuleIds], []);
  assert.equal(next.candidates.some((candidate) => candidate.ruleId === "sast_sql_template_interpolation"), true);
});

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

test("detects pip install references in Python automation, notebooks, and deployment scripts", async () => {
  const source = `
subprocess.run("python -m pip install torch-vision-utils requests")
subprocess.run(["pip", "install", "fastapi-limiter-middleware"])
!pip install django-secure-auth
# pip install ignored-comment-package
`;
  const references = parsePackageReferences("bootstrap.py", source, "python");

  assert.deepEqual(
    references.map((reference) => [reference.registry, reference.packageName, reference.source]),
    [
      ["pypi", "torch-vision-utils", "install"],
      ["pypi", "requests", "install"],
      ["pypi", "fastapi-limiter-middleware", "install"],
      ["pypi", "django-secure-auth", "install"]
    ]
  );

  const result = await scanSourceFile(
    {
      filePath: "bootstrap.py",
      languageId: "python",
      text: source
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1
    }
  );

  assert.deepEqual(
    result.findings.map((finding) => finding.evidence),
    ["torch-vision-utils", "fastapi-limiter-middleware", "django-secure-auth"]
  );

  const deploymentReferences = [
    ["Dockerfile", "dockerfile", "RUN python -m pip install torch-vision-utils requests"],
    ["bootstrap.sh", "shellscript", "pip3 install django-secure-auth"],
    ["deploy.yml", "yaml", "- run: pip install fastapi-limiter-middleware"]
  ].flatMap(([filePath, languageId, text]) => parsePackageReferences(filePath, text, languageId));
  assert.deepEqual(
    deploymentReferences.map((reference) => [reference.registry, reference.packageName, reference.source]),
    [
      ["pypi", "torch-vision-utils", "install"],
      ["pypi", "requests", "install"],
      ["pypi", "django-secure-auth", "install"],
      ["pypi", "fastapi-limiter-middleware", "install"]
    ]
  );
});

test("detects hallucinated pip packages from deployment files", async () => {
  const result = await scanSourceFile(
    {
      filePath: "Dockerfile",
      languageId: "dockerfile",
      text: "RUN pip install torch-vision-utils"
    },
    { packageVerification: "seed", includeSast: false, now: 1 }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detection_rule, "hallucinated_package_pypi");
  assert.match(result.findings[0].suggestion ?? "", /torchvision/);
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

test("bounds package verification work to five concurrent references while keeping finding order", async () => {
  let active = 0;
  let peak = 0;
  const verified: string[] = [];
  const packageVerifier = {
    verify: async (reference: PackageReference) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      verified.push(reference.packageName);
      return {
        registry: reference.registry,
        packageName: reference.packageName,
        exists: false,
        source: "remote" as const,
        lastVerified: 1
      };
    }
  };
  const names = ["remote-one", "remote-two", "remote-three", "remote-four", "remote-five", "remote-six", "remote-seven"];
  const result = await scanSourceFile(
    {
      filePath: "packages.ts",
      languageId: "typescript",
      text: names.map((name, index) => `import package${index} from "${name}";`).join("\n")
    },
    {
      packageVerification: "remote",
      includeSast: false,
      packageVerifier,
      now: 1
    }
  );

  assert.equal(peak, 5);
  assert.deepEqual(verified.sort(), [...names].sort());
  assert.deepEqual(result.findings.map((finding) => finding.evidence), names);
});

test("caps PackageVerifier remote registry requests for concurrent callers", async () => {
  let active = 0;
  let peak = 0;
  const verifier = new PackageVerifier({
    maxConcurrentRemoteRequests: 2,
    fetchImpl: async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return new Response("{}", { status: 404 });
    }
  });
  const names = ["unknown-one", "unknown-two", "unknown-three", "unknown-four", "unknown-five"];

  const results = await Promise.all(
    names.map((packageName) =>
      verifier.verify(
        {
          registry: "npm",
          packageName,
          rawSpecifier: packageName,
          line: 1,
          column: 1,
          endLine: 1,
          endColumn: packageName.length + 1,
          source: "import"
        },
        "remote"
      )
    )
  );

  assert.equal(peak, 2);
  assert.equal(results.every((result) => result.exists === false), true);
});

test("coalesces concurrent verification of the same remote package", async () => {
  let calls = 0;
  const verifier = new PackageVerifier({
    fetchImpl: async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return new Response("{}", { status: 200 });
    }
  });
  const reference: PackageReference = {
    registry: "npm",
    packageName: "remote-only-package",
    rawSpecifier: "remote-only-package",
    line: 1,
    column: 1,
    endLine: 1,
    endColumn: 20,
    source: "import"
  };

  const results = await Promise.all(Array.from({ length: 8 }, () => verifier.verify(reference, "remote")));

  assert.equal(calls, 1);
  assert.equal(results.every((result) => result.exists === true), true);
});

test("reports unavailable remote package verification without misclassifying the package as hallucinated", async () => {
  const result = await scanSourceFile(
    {
      filePath: "packages.ts",
      languageId: "typescript",
      text: 'import packageName from "remote-only-package";'
    },
    {
      packageVerification: "remote",
      includeSast: false,
      packageVerifier: {
        verify: async (reference) => ({
          registry: reference.registry,
          packageName: reference.packageName,
          exists: null,
          source: "unverified",
          lastVerified: 1,
          message: "Remote package verification timed out."
        })
      },
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].type, "other");
  assert.equal(result.findings[0].severity, "medium");
  assert.equal(result.findings[0].detection_rule, "package_verification_unavailable_npm");
  assert.match(result.findings[0].suggestion ?? "", /timed out/i);
  assert.equal(result.findings.some((finding) => finding.type === "hallucinated_package"), false);
});

test("retries remote package verification after connectivity recovers instead of caching an unavailable result", async () => {
  const cached = new Map<string, import("../src/types").PackageResolution>();
  const cache: PackageCacheStore = {
    get: async (registry, packageName) => cached.get(`${registry}:${packageName}`),
    set: async (resolution) => {
      cached.set(`${resolution.registry}:${resolution.packageName}`, resolution);
    }
  };
  let calls = 0;
  const verifier = new PackageVerifier({
    cache,
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) {
        throw new Error("network offline");
      }
      return new Response("{}", { status: 200 });
    }
  });
  const reference: PackageReference = {
    registry: "npm",
    packageName: "remote-only-package",
    rawSpecifier: "remote-only-package",
    line: 1,
    column: 1,
    endLine: 1,
    endColumn: 20,
    source: "import"
  };

  const unavailable = await verifier.verify(reference, "remote");
  const verified = await verifier.verify(reference, "remote");

  assert.equal(unavailable.exists, null);
  assert.equal(verified.exists, true);
  assert.equal(calls, 2);
  assert.equal(cached.size, 1);
  assert.equal(cached.get("npm:remote-only-package")?.exists, true);
});

test("remotely verifies unknown Cargo, Go, and Maven package references", async () => {
  const requestedUrls: string[] = [];
  const verifier = new PackageVerifier({
    fetchImpl: async (url) => {
      const value = String(url);
      requestedUrls.push(value);
      if (value.startsWith("https://search.maven.org/")) {
        return new Response(JSON.stringify({ response: { numFound: 1, docs: [{ g: "com.example", a: "remote-artifact" }] } }), {
          status: 200
        });
      }
      return new Response("{}", { status: 200 });
    }
  });
  const references: PackageReference[] = [
    packageReference("cargo", "remote-cargo-package"),
    packageReference("gomod", "example.com/Acme/RemotePackage"),
    packageReference("maven", "com.example:remote-artifact")
  ];

  const results = await Promise.all(references.map((reference) => verifier.verify(reference, "remote")));

  assert.equal(results.every((result) => result.exists === true && result.source === "remote"), true);
  assert.equal(requestedUrls.some((url) => url === "https://crates.io/api/v1/crates/remote-cargo-package"), true);
  assert.equal(
    requestedUrls.some((url) => url === "https://proxy.golang.org/example.com/!acme/!remote!package/@latest"),
    true
  );
  const mavenUrl = new URL(requestedUrls.find((url) => url.startsWith("https://search.maven.org/")) ?? "https://invalid.test");
  assert.equal(mavenUrl.searchParams.get("q"), 'g:"com.example" AND a:"remote-artifact"');
  assert.equal(mavenUrl.searchParams.get("rows"), "1");
});

test("caches only definitive missing results from extended remote registries", async () => {
  const calls = new Map<string, number>();
  const verifier = new PackageVerifier({
    fetchImpl: async (url) => {
      const value = String(url);
      const registry = value.includes("crates.io") ? "cargo" : value.includes("search.maven.org") ? "maven" : "gomod";
      calls.set(registry, (calls.get(registry) ?? 0) + 1);
      if (registry === "cargo") {
        return new Response("{}", { status: 404 });
      }
      if (registry === "maven") {
        return new Response(JSON.stringify({ response: { numFound: 0, docs: [] } }), { status: 200 });
      }
      return new Response("rate limited", { status: 429 });
    }
  });
  const cargo = packageReference("cargo", "missing-cargo-package");
  const maven = packageReference("maven", "com.example:missing-artifact");
  const gomod = packageReference("gomod", "example.com/blocked/module");

  const [missingCargo, missingMaven, unavailableGo] = await Promise.all([
    verifier.verify(cargo, "remote"),
    verifier.verify(maven, "remote"),
    verifier.verify(gomod, "remote")
  ]);
  await Promise.all([verifier.verify(cargo, "remote"), verifier.verify(maven, "remote"), verifier.verify(gomod, "remote")]);

  assert.equal(missingCargo.exists, false);
  assert.equal(missingMaven.exists, false);
  assert.match(missingMaven.message ?? "", /no matching coordinate/i);
  assert.equal(unavailableGo.exists, null);
  assert.equal(unavailableGo.source, "unverified");
  assert.equal(calls.get("cargo"), 1);
  assert.equal(calls.get("maven"), 1);
  assert.equal(calls.get("gomod"), 2);
});

test("keeps unknown seed-mode packages quiet until remote verification is requested", async () => {
  const result = await scanSourceFile(
    {
      filePath: "packages.ts",
      languageId: "typescript",
      text: 'import packageName from "not-in-the-seed-catalog";'
    },
    {
      packageVerification: "seed",
      includeSast: false,
      packageVerifier: {
        verify: async (reference) => ({
          registry: reference.registry,
          packageName: reference.packageName,
          exists: null,
          source: "unverified",
          lastVerified: 1
        })
      },
      now: 1
    }
  );

  assert.deepEqual(result.findings, []);
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

test("matches Rust crate imports to hyphenated Cargo seed package names", async () => {
  const validReference = parsePackageReferences("main.rs", "use actix_web::App;", "rust")[0];
  assert.ok(validReference);
  const validResolution = await new PackageVerifier().verify(validReference, "seed");
  assert.equal(validResolution.exists, true);
  assert.equal(validResolution.source, "seed");

  const result = await scanSourceFile(
    {
      filePath: "main.rs",
      languageId: "rust",
      text: "use actix_web_secure_middleware::Auth;"
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1
    }
  );

  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detection_rule, "hallucinated_package_cargo");
  assert.match(result.findings[0].suggestion ?? "", /actix-web/);
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

test("detects hallucinated Maven packages from a Gradle version catalog", async () => {
  const result = await scanSourceFile(
    {
      filePath: "gradle/libs.versions.toml",
      languageId: "toml",
      text: `[versions]
spring = "3.3.0"

[libraries]
spring-web = { module = "org.springframework.boot:spring-boot-starter-web", version.ref = "spring" }
spring-secure = { group = "org.springframework.boot", name = "spring-boot-starter-secure-api", version.ref = "spring" }
logging = "org.slf4j:slf4j-api:2.0.13"

[plugins]
spring-boot = { id = "org.springframework.boot", version.ref = "spring" }
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
  assert.match(result.findings[0].suggestion ?? "", /spring-boot-starter-security/);
});

test("parses only exact external Java class imports for Maven verification", () => {
  const references = parsePackageReferences(
    "Controller.java",
    `import java.util.List;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import static org.mockito.Mockito.when;
import com.example.widgets.*;
import org.springframework.web.bind.annotation.RestController;
import com.example.widgets.RemoteWidget;
import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBContext;
`,
    "java"
  );

  assert.deepEqual(
    references.map((reference) => [reference.registry, reference.packageName, reference.mavenLookup, reference.source]),
    [
      ["maven", "org.springframework.web.bind.annotation.RestController", "class", "import"],
      ["maven", "com.example.widgets.RemoteWidget", "class", "import"],
      ["maven", "javax.servlet.http.HttpServletRequest", "class", "import"],
      ["maven", "javax.xml.bind.JAXBContext", "class", "import"]
    ]
  );
});

test("parses exact external Kotlin class imports for Maven verification", () => {
  const references = parsePackageReferences(
    "Controller.kt",
    `import java.time.Instant
import kotlin.collections.List
import android.content.Context
import androidx.lifecycle.ViewModel
import org.springframework.web.bind.annotation.RestController as SpringController
import com.example.widgets.RemoteWidget
import com.example.functions.helper
import com.example.widgets.*
import com.example.widgets.TopLevelKt
`,
    "kotlin"
  );

  assert.deepEqual(
    references.map((reference) => [reference.registry, reference.packageName, reference.mavenLookup, reference.source]),
    [
      ["maven", "org.springframework.web.bind.annotation.RestController", "class", "import"],
      ["maven", "com.example.widgets.RemoteWidget", "class", "import"],
      ["maven", "com.example.widgets.TopLevelKt", "class", "import"]
    ]
  );
});

test("remotely verifies Java class imports without using coordinate indexes", async () => {
  const requestedQueries: string[] = [];
  const packageIndex = {
    get: async () => false,
    coverage: async () => "full" as const
  };
  const verifier = new PackageVerifier({
    packageIndex,
    fetchImpl: async (url) => {
      const query = new URL(String(url)).searchParams.get("q") ?? "";
      requestedQueries.push(query);
      const exists = query.includes("KnownRemoteComponent");
      return new Response(JSON.stringify({ response: { numFound: exists ? 1 : 0, docs: [] } }), { status: 200 });
    }
  });
  const source = {
    filePath: "ImportController.java",
    languageId: "java",
    text: `import com.example.KnownRemoteComponent;
import com.example.MissingRemoteComponent;
import java.util.List;
import javax.crypto.Cipher;
import org.w3c.dom.Document;
class ImportController {}`
  };

  const first = await scanSourceFile(source, {
    packageVerification: "remote",
    includeSast: false,
    packageVerifier: verifier,
    now: 1
  });
  const second = await scanSourceFile(source, {
    packageVerification: "remote",
    includeSast: false,
    packageVerifier: verifier,
    now: 2
  });

  assert.deepEqual(requestedQueries.sort(), [
    'fc:"com.example.KnownRemoteComponent"',
    'fc:"com.example.MissingRemoteComponent"'
  ]);
  assert.equal(first.findings.length, 1);
  assert.equal(first.findings[0].detection_rule, "hallucinated_package_maven");
  assert.equal(first.findings[0].evidence, "com.example.MissingRemoteComponent");
  assert.match(first.findings[0].suggestion ?? "", /no matching imported class/i);
  assert.equal(second.findings.length, 1);
});

test("remotely verifies Kotlin class imports through the Maven class index", async () => {
  const requestedQueries: string[] = [];
  const verifier = new PackageVerifier({
    packageIndex: {
      get: async () => false,
      coverage: async () => "full" as const
    },
    fetchImpl: async (url) => {
      const query = new URL(String(url)).searchParams.get("q") ?? "";
      requestedQueries.push(query);
      const exists = query.includes("KnownRemoteComponent");
      return new Response(JSON.stringify({ response: { numFound: exists ? 1 : 0, docs: [] } }), { status: 200 });
    }
  });
  const result = await scanSourceFile(
    {
      filePath: "ImportController.kt",
      languageId: "kotlin",
      text: `import com.example.KnownRemoteComponent as Known
import com.example.MissingRemoteComponent
import kotlin.collections.List
class ImportController`
    },
    {
      packageVerification: "remote",
      includeSast: false,
      packageVerifier: verifier,
      now: 1
    }
  );

  assert.deepEqual(requestedQueries.sort(), [
    'fc:"com.example.KnownRemoteComponent"',
    'fc:"com.example.MissingRemoteComponent"'
  ]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].detection_rule, "hallucinated_package_maven");
  assert.equal(result.findings[0].evidence, "com.example.MissingRemoteComponent");
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

test("offers each verified similar package as a safe hallucinated-package replacement", async () => {
  const result = await scanSourceFile(
    {
      filePath: "app.ts",
      languageId: "typescript",
      text: 'import Widget from "invented-ui-widget";'
    },
    {
      packageVerification: "seed",
      includeSast: false,
      now: 1,
      packageVerifier: {
        async verify(reference) {
          return {
            registry: reference.registry,
            packageName: reference.packageName,
            exists: false,
            source: "index",
            lastVerified: 1,
            similarPackages: ["react-window", "react-virtualized", "react-window", "not a package"]
          };
        }
      }
    }
  );
  const finding = result.findings.find((item) => item.detection_rule === "hallucinated_package_npm");

  assert.equal(finding?.fix?.description, "Replace with react-window");
  assert.deepEqual(finding?.fix?.edits[0]?.newText, "react-window");
  assert.deepEqual(
    finding?.alternativeFixes?.map((fix) => [fix.description, fix.edits[0]?.newText]),
    [["Replace with react-virtualized", "react-virtualized"]]
  );
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

test("keeps the AI-pattern library above the PRD's 30-rule target", () => {
  assert.equal(aiPatternRules.length >= 30, true);
});

test("detects additional high-confidence AI security anti-patterns", async () => {
  const sources = [
    {
      filePath: "server.ts",
      languageId: "typescript",
      text: `
res.cookie("session", value, { secure: false, httpOnly: false });
spawn("deploy", ["--target", target], { shell: true });
app.use(helmet({ contentSecurityPolicy: false }));
s3.putObject({ Bucket, Key, ACL: "public-read-write" });
`
    },
    {
      filePath: "SecurityConfig.java",
      languageId: "java",
      text: `http.csrf(AbstractHttpConfigurer::disable);`
    },
    {
      filePath: "app.py",
      languageId: "python",
      text: `
from jinja2 import Environment
environment = Environment(autoescape=False)
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
reset_token = random.choice(chars)
SESSION_COOKIE_SECURE = False
session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
`
    }
  ];

  const ruleIds = new Set<string>();
  for (const source of sources) {
    const result = await scanSourceFile(source, {
      packageVerification: "off",
      includeSast: false,
      now: 1
    });
    for (const finding of result.findings) {
      ruleIds.add(finding.detection_rule);
    }
  }

  for (const ruleId of [
    "ai_pattern_cookie_secure_false",
    "ai_pattern_cookie_httponly_false",
    "ai_pattern_child_process_shell_true",
    "ai_pattern_helmet_csp_disabled",
    "ai_pattern_object_storage_public_write_acl",
    "ai_pattern_spring_csrf_disabled",
    "ai_pattern_jinja_autoescape_disabled",
    "ai_pattern_paramiko_auto_add_host_key",
    "ai_pattern_python_weak_random_token",
    "ai_pattern_django_session_cookie_secure_false",
    "ai_pattern_sqlalchemy_text_f_string"
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
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

test("uses Tree-sitter AST nodes for JavaScript SAST findings", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `
// const query = \`SELECT * FROM users WHERE id = \${req.query.id}\`;
const copy = "element.innerHTML = req.query.name";
const query = \`SELECT * FROM users WHERE id = \${req.query.id}\`;
element.innerHTML = req.query.name;
`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const sqlFindings = result.findings.filter((finding) => finding.detection_rule === "sast_sql_template_interpolation");
  const htmlFindings = result.findings.filter((finding) => finding.detection_rule === "sast_xss_inner_html");
  assert.equal(sqlFindings.length, 1);
  assert.equal(htmlFindings.length, 1);
  assert.match(sqlFindings[0].evidence, /^query/);
  assert.match(htmlFindings[0].evidence, /^\.innerHTML/);
});

test("uses Tree-sitter AST nodes for Python f-string SQL detection", async () => {
  const result = await scanSourceFile(
    {
      filePath: "repository.py",
      languageId: "python",
      text: `
# session.execute(f"SELECT * FROM users WHERE id = {user_id}")
session.execute(
    f"SELECT * FROM users WHERE id = {user_id}"
)
`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const findings = result.findings.filter((finding) => finding.detection_rule === "sast_sql_python_f_string_execute");
  assert.equal(findings.length, 1);
  assert.match(findings[0].evidence, /^session\.execute/);
});

test("adds a safe SQLite parameterization fix for a single Python SQL f-string expression", async () => {
  const source = `import sqlite3
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`;
  const result = await scanSourceFile(
    {
      filePath: "repository.py",
      languageId: "python",
      text: source
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "sast_sql_python_f_string_execute");
  assert.equal(finding?.fix?.edits[0].newText, 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))');
  assert.equal(
    applyFirstFix(source, finding),
    'import sqlite3\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
  );
});

test("does not auto-fix Python SQL f-strings without a known SQLite placeholder dialect", async () => {
  const result = await scanSourceFile(
    {
      filePath: "repository.py",
      languageId: "python",
      text: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "sast_sql_python_f_string_execute");
  assert.equal(finding?.fix, undefined);
});

test("tracks local request aliases into JavaScript and Python SQL execution sinks", async () => {
  const sources = [
    {
      filePath: "repository.ts",
      languageId: "typescript",
      text: `
const userId = req.query.id;
const rawSql = "SELECT * FROM users WHERE id = " + userId;
db.query(rawSql);`
    },
    {
      filePath: "repository.py",
      languageId: "python",
      text: `
user_id = request.args["id"]
raw_sql = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(raw_sql)
`
    }
  ];

  for (const source of sources) {
    const result = await scanSourceFile(source, {
      packageVerification: "off",
      includeSast: true,
      now: 1
    });
    const finding = result.findings.find((item) => item.detection_rule === "sast_sql_user_input_execute");
    assert.equal(finding?.type, "sql_injection");
    assert.equal(finding?.severity, "high");
  }
});

test("does not flag parameterized JavaScript or Python SQL calls as user-controlled SQL execution", async () => {
  const sources = [
    {
      filePath: "repository.ts",
      languageId: "typescript",
      text: `
const userId = req.query.id;
db.query("SELECT * FROM users WHERE id = ?", [userId]);`
    },
    {
      filePath: "repository.py",
      languageId: "python",
      text: `
user_id = request.args["id"]
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
`
    }
  ];

  for (const source of sources) {
    const result = await scanSourceFile(source, {
      packageVerification: "off",
      includeSast: true,
      now: 1
    });
    assert.equal(result.findings.some((item) => item.detection_rule === "sast_sql_user_input_execute"), false);
  }
});

test("detects user-controlled Node filesystem writes and deletes through local aliases", async () => {
  const [unsafe, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "uploads.ts",
        languageId: "typescript",
        text: `
async function store(req: Request) {
  const fileName = req.body.fileName;
  await fs.promises.writeFile(path.join("/srv/uploads", fileName), req.body.contents);
  fs.rmSync(path.join("/srv/uploads", fileName));
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "safe-uploads.ts",
        languageId: "typescript",
        text: `
async function store(contents: string) {
  const fileName = createStorageName();
  await fs.promises.writeFile(path.join("/srv/uploads", fileName), contents);
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  const findings = unsafe.findings.filter((finding) => finding.detection_rule === "sast_path_traversal_fs_user_input");
  assert.equal(findings.length, 2);
  assert.equal(findings.every((finding) => finding.type === "path_traversal" && finding.severity === "high"), true);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === "sast_path_traversal_fs_user_input"), false);
});

test("detects user-controlled SSRF targets across common Node and Python HTTP clients", async () => {
  const [unsafeJavaScript, unsafePython, safeJavaScript] = await Promise.all([
    scanSourceFile(
      {
        filePath: "proxy.ts",
        languageId: "typescript",
        text: `
async function proxy(req: Request) {
  const target = req.query.target;
  await axios.request({ url: target });
  https.request({ hostname: req.query.host });
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "proxy.py",
        languageId: "python",
        text: `
target = request.args["target"]
httpx.patch(target)
requests.request("GET", target)
`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "safe-proxy.ts",
        languageId: "typescript",
        text: `
async function proxy(req: Request) {
  await axios.request({ url: "https://api.company.test", data: req.body.payload });
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  const rule = "sast_ssrf_fetch_user_url";
  assert.equal(unsafeJavaScript.findings.filter((finding) => finding.detection_rule === rule).length, 2);
  assert.equal(unsafePython.findings.filter((finding) => finding.detection_rule === rule).length, 2);
  assert.equal(safeJavaScript.findings.some((finding) => finding.detection_rule === rule), false);
});

test("detects user-controlled synchronous command execution APIs", async () => {
  const [unsafeJavaScript, unsafePython, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "admin.ts",
        languageId: "typescript",
        text: `
function run(req: Request) {
  const command = req.body.command;
  child_process.execSync(command);
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "admin.py",
        languageId: "python",
        text: `
command = request.args["command"]
subprocess.check_output(command, shell=True)
subprocess.check_call(command, shell=True)
`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "safe-admin.ts",
        languageId: "typescript",
        text: "child_process.execSync(\"git status --short\");"
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  const rule = "sast_command_injection_os_system";
  assert.equal(unsafeJavaScript.findings.some((finding) => finding.detection_rule === rule), true);
  assert.equal(unsafePython.findings.filter((finding) => finding.detection_rule === rule).length, 2);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === rule), false);
});

test("detects user-controlled Node spawn and execFile calls only in shell mode", async () => {
  const [unsafe, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "deploy.ts",
        languageId: "typescript",
        text: `
function deploy(req: Request) {
  const target = req.query.target;
  child_process.spawn("deploy", ["--target", target], { shell: true });
  child_process.spawnSync(req.body.command, [], { shell: true });
  child_process.execFile("deploy", ["--target", target], { shell: true });
  child_process.execFileSync(req.body.command, [], { shell: true });
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "safe-deploy.ts",
        languageId: "typescript",
        text: `
function deploy(req: Request) {
  const target = req.query.target;
  child_process.spawn("deploy", ["--target", target]);
  child_process.execFile("deploy", ["--target", target]);
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  const rule = "sast_command_injection_os_system";
  assert.equal(unsafe.findings.filter((finding) => finding.detection_rule === rule).length, 4);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === rule), false);
});

test("detects direct Java request input in JDBC, process execution, and ObjectInputStream sinks", async () => {
  const [unsafe, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "AdminController.java",
        languageId: "java",
        text: `class AdminController {
  void handle(HttpServletRequest request, Statement statement) throws Exception {
    statement.executeQuery("SELECT * FROM users WHERE id = " + request.getParameter("id"));
    Runtime.getRuntime().exec(request.getParameter("command"));
    new ObjectInputStream(request.getInputStream()).readObject();
    Files.readAllBytes(Paths.get(request.getParameter("path")));
    Files.write(Paths.get(request.getParameter("target")), new byte[0]);
  }
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "SafeController.java",
        languageId: "java",
        text: `class SafeController {
  void handle(PreparedStatement statement, byte[] payload) throws Exception {
    statement.executeQuery();
    Runtime.getRuntime().exec(new String[] { "echo", "safe" });
    new ObjectInputStream(new ByteArrayInputStream(payload)).readObject();
    Files.readAllBytes(Paths.get("/srv/app/fixed.txt"));
  }
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  const ruleIds = new Set(unsafe.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("sast_sql_user_input_execute"), true);
  assert.equal(ruleIds.has("sast_command_injection_os_system"), true);
  assert.equal(ruleIds.has("sast_insecure_deserialization_java_object_input_stream"), true);
  assert.equal(unsafe.findings.filter((finding) => finding.detection_rule === "sast_path_traversal_java_request_input").length, 2);
  assert.equal(safe.findings.some((finding) => finding.detection_layer === "L2"), false);
});

test("detects Java request URLs passed to common outbound HTTP clients", async () => {
  const [unsafe, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "ProxyController.java",
        languageId: "java",
        text: `class ProxyController {
  void fetch(HttpServletRequest request) {
    restTemplate.getForObject(request.getParameter("url"), String.class);
    webClient.get().uri(request.getParameter("endpoint")).retrieve();
    HttpRequest.newBuilder(URI.create(request.getParameter("target"))).build();
  }
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "SafeProxyController.java",
        languageId: "java",
        text: `class SafeProxyController {
  void fetch() {
    restTemplate.getForObject("https://api.example.test/health", String.class);
    webClient.get().uri("/status").retrieve();
    HttpRequest.newBuilder(URI.create("https://api.example.test/status")).build();
  }
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  assert.equal(unsafe.findings.filter((finding) => finding.detection_rule === "sast_ssrf_java_request_url").length, 3);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === "sast_ssrf_java_request_url"), false);
});

test("detects Java request redirects and exposed exception messages", async () => {
  const [unsafe, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "LoginController.java",
        languageId: "java",
        text: `class LoginController {
  void complete(HttpServletRequest request, HttpServletResponse response, RuntimeException sqlException) throws Exception {
    response.sendRedirect(request.getParameter("next"));
    RedirectView view = new RedirectView(request.getParameter("returnTo"));
    response.sendError(500, sqlException.getMessage());
  }

  String finish(HttpServletRequest request) {
    return "redirect:" + request.getParameter("continue");
  }

  ResponseEntity<Object> fail(RuntimeException sqlException) {
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(sqlException.getMessage());
  }
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "SafeLoginController.java",
        languageId: "java",
        text: `class SafeLoginController {
  void complete(HttpServletResponse response) throws Exception {
    response.sendRedirect("/dashboard");
    RedirectView view = new RedirectView("/profile");
    response.sendError(500, "Request could not be completed.");
  }

  String finish() {
    return "redirect:/profile";
  }

  ResponseEntity<String> fail() {
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Request could not be completed.");
  }
}`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  assert.equal(unsafe.findings.filter((finding) => finding.detection_rule === "sast_open_redirect_java_request_input").length, 3);
  assert.equal(unsafe.findings.filter((finding) => finding.detection_rule === "sast_information_leakage_java_error_details").length, 2);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === "sast_open_redirect_java_request_input"), false);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === "sast_information_leakage_java_error_details"), false);
});

test("detects user-controlled dangerouslySetInnerHTML through a local alias", async () => {
  const result = await scanSourceFile(
    {
      filePath: "profile.tsx",
      languageId: "typescriptreact",
      text: `
function Profile(req: Request) {
  const profileHtml = req.query.profile;
  return <article dangerouslySetInnerHTML={{ __html: profileHtml }} />;
}`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const finding = result.findings.find((item) => item.detection_rule === "sast_xss_dangerously_set_inner_html");
  assert.equal(finding?.type, "xss");
  assert.equal(finding?.severity, "high");
  assert.match(finding?.evidence ?? "", /^dangerouslySetInnerHTML/);
});

test("does not report direct sanitizer use in dangerouslySetInnerHTML as L2 XSS", async () => {
  const result = await scanSourceFile(
    {
      filePath: "profile.tsx",
      languageId: "typescriptreact",
      text: `
function Profile(req: Request) {
  return <article dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(req.query.profile) }} />;
}`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  assert.equal(result.findings.some((item) => item.detection_rule === "sast_xss_dangerously_set_inner_html"), false);
});

test("tracks JavaScript request-input aliases into L2 sinks within the same scope", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `
app.get("/proxy", (req, res) => {
  const remoteUrl = req.query.url;
  const outboundUrl = remoteUrl;
  const fileName = req.params.file;
  const command = req.body.command;
  const redirectTarget = req.query.next;
  fetch(outboundUrl);
  fs.readFile(fileName);
  exec(command);
  res.redirect(redirectTarget);
});`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const ruleIds = new Set(result.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("sast_ssrf_fetch_user_url"), true);
  assert.equal(ruleIds.has("sast_path_traversal_fs_user_input"), true);
  assert.equal(ruleIds.has("sast_command_injection_os_system"), true);
  assert.equal(ruleIds.has("sast_open_redirect_user_input"), true);
});

test("tracks Python request-input aliases into L2 sinks within the same scope", async () => {
  const result = await scanSourceFile(
    {
      filePath: "views.py",
      languageId: "python",
      text: `
def proxy():
    remote_url = request.args.get("url")
    outbound_url = remote_url
    file_name = request.args["file"]
    command = request.form["command"]
    redirect_target = request.args.get("next")
    requests.get(outbound_url)
    open(file_name)
    subprocess.run(command, shell=True)
    redirect(redirect_target)
`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  const ruleIds = new Set(result.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("sast_ssrf_fetch_user_url"), true);
  assert.equal(ruleIds.has("sast_path_traversal_fs_user_input"), true);
  assert.equal(ruleIds.has("sast_command_injection_os_system"), true);
  assert.equal(ruleIds.has("sast_open_redirect_user_input"), true);
});

test("does not treat a tainted name in another function as a local source", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `
function requestHandler(req: Request) {
  const target = req.query.url;
  return target;
}
function systemHealthCheck() {
  const target = "https://status.example.test";
  return fetch(target);
}`
    },
    {
      packageVerification: "off",
      includeSast: true,
      now: 1
    }
  );

  assert.equal(result.findings.some((finding) => finding.detection_rule === "sast_ssrf_fetch_user_url"), false);
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
  assert.equal(finding?.fix?.edits[0].newText, "yaml.safe_load(request.data)");
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

test("detects SQL and sensitive diagnostics only when returned through an error response", async () => {
  const [javascript, python, safe] = await Promise.all([
    scanSourceFile(
      {
        filePath: "errors.ts",
        languageId: "typescript",
        text: `app.get("/debug", (req, res) => {
  try {
    runQuery();
  } catch (error) {
    res.status(500).json({ error: error.message, sql: query, connectionString: databaseUrl });
  }
});`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "errors.py",
        languageId: "python",
        text: `@app.get("/debug")
def debug():
    try:
        run_query()
    except Exception as error:
        return {"error": str(error), "query": query, "database_url": database_url}
`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    ),
    scanSourceFile(
      {
        filePath: "safe-errors.ts",
        languageId: "typescript",
        text: `app.get("/debug", (req, res) => {
  res.status(500).json({ error: "Request failed." });
  res.json({ token: sessionToken });
});`
      },
      { packageVerification: "off", includeSast: true, now: 1 }
    )
  ]);

  assert.equal(javascript.findings.some((finding) => finding.detection_rule === "sast_information_leakage_error_details"), true);
  assert.equal(python.findings.some((finding) => finding.detection_rule === "sast_information_leakage_error_details"), true);
  assert.equal(safe.findings.some((finding) => finding.detection_rule === "sast_information_leakage_error_details"), false);
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

test("uses scoped Express authentication and rate-limit middleware in local L3 checks", async () => {
  const result = await scanSourceFile(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: `
app.use("/api", requireAuth);
app.use("/api", rateLimit({ windowMs: 60_000 }));

app.post("/api/admin/users", (req, res) => {
  res.json({ email: req.body.email });
});

app.post("/public/admin/users", (req, res) => {
  res.json({ email: req.body.email });
});
`
    },
    {
      packageVerification: "off",
      detectionLayers: { l1: false, l2: false, l3: true },
      now: 1
    }
  );

  const apiRuleIds = new Set(
    result.findings.filter((finding) => finding.evidence.includes('"/api/admin/users"')).map((finding) => finding.detection_rule)
  );
  const publicRuleIds = new Set(
    result.findings.filter((finding) => finding.evidence.includes('"/public/admin/users"')).map((finding) => finding.detection_rule)
  );
  assert.equal(apiRuleIds.has("l3_missing_authentication"), false);
  assert.equal(apiRuleIds.has("l3_missing_rate_limiting"), false);
  assert.equal(apiRuleIds.has("l3_missing_input_validation"), true);
  assert.equal(publicRuleIds.has("l3_missing_authentication"), true);
  assert.equal(publicRuleIds.has("l3_missing_rate_limiting"), true);
});

test("applies local L3 security-dimension checks to Spring controller endpoints", async () => {
  const [unsafe, protectedEndpoint] = await Promise.all([
    scanSourceFile(
      {
        filePath: "AdminController.java",
        languageId: "java",
        text: `
@RestController
@RequestMapping("/api/admin")
public class AdminController {
  @PostMapping("/users")
  public ResponseEntity<User> createUser(@RequestBody User input) {
    return ResponseEntity.ok(repository.save(input));
  }
}
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    ),
    scanSourceFile(
      {
        filePath: "AdminController.java",
        languageId: "java",
        text: `
@RestController
@RequestMapping("/api/admin")
public class AdminController {
  @PostMapping("/users")
  @PreAuthorize("hasRole('ADMIN')")
  @RateLimiter(name = "adminWrite")
  public ResponseEntity<User> createUser(@Valid @RequestBody User input) {
    try {
      return ResponseEntity.ok(repository.save(input));
    } catch (DataAccessException error) {
      return ResponseEntity.status(500).build();
    }
  }
}
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    )
  ]);

  const unsafeRules = new Set(unsafe.findings.map((finding) => finding.detection_rule));
  const protectedRules = new Set(protectedEndpoint.findings.map((finding) => finding.detection_rule));
  assert.equal(unsafeRules.has("l3_missing_authentication"), true);
  assert.equal(unsafeRules.has("l3_missing_rate_limiting"), true);
  assert.equal(unsafeRules.has("l3_missing_input_validation"), true);
  assert.equal(unsafeRules.has("l3_missing_error_handling"), true);
  assert.equal(protectedRules.has("l3_missing_authentication"), false);
  assert.equal(protectedRules.has("l3_missing_rate_limiting"), false);
  assert.equal(protectedRules.has("l3_missing_input_validation"), false);
  assert.equal(protectedRules.has("l3_missing_error_handling"), false);
});

test("detects local L3 missing parameterization and error handling for request-driven IO", async () => {
  const result = await scanSourceFile(
    {
      filePath: "orders.ts",
      languageId: "typescript",
      text: `
app.post("/orders", async (req, res) => {
  const orderId = req.body.orderId;
  const query = \`SELECT * FROM orders WHERE id = \${orderId}\`;
  const order = await db.query(query);
  const inventory = await fetch(\`https://inventory.example.test/orders/\${orderId}\`);
  res.json({ order, inventory });
});`
    },
    {
      packageVerification: "off",
      detectionLayers: { l1: false, l2: false, l3: true },
      now: 1
    }
  );

  const ruleIds = new Set(result.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("l3_missing_parameterized_queries"), true);
  assert.equal(ruleIds.has("l3_missing_error_handling"), true);
});

test("recognizes parameterized database calls and explicit IO handling in local L3 analysis", async () => {
  const result = await scanSourceFile(
    {
      filePath: "orders.ts",
      languageId: "typescript",
      text: `
app.post("/orders", async (req, res) => {
  const orderId = req.body.orderId;
  try {
    const order = await db.query("SELECT * FROM orders WHERE id = ?", [orderId]);
    const inventory = await fetch(\`https://inventory.example.test/orders/\${orderId}\`);
    res.json({ order, inventory });
  } catch (error) {
    res.status(502).json({ error: "upstream unavailable" });
  }
});`
    },
    {
      packageVerification: "off",
      detectionLayers: { l1: false, l2: false, l3: true },
      now: 1
    }
  );

  const ruleIds = new Set(result.findings.map((finding) => finding.detection_rule));
  assert.equal(ruleIds.has("l3_missing_parameterized_queries"), false);
  assert.equal(ruleIds.has("l3_missing_error_handling"), false);
});

test("applies local L3 query and IO heuristics to Python route handlers", async () => {
  const unsafe = await scanSourceFile(
    {
      filePath: "orders.py",
      languageId: "python",
      text: `
@app.post("/orders")
def get_order():
    order_id = request.json["order_id"]
    query = f"SELECT * FROM orders WHERE id = {order_id}"
    return cursor.execute(query)
`
    },
    {
      packageVerification: "off",
      detectionLayers: { l1: false, l2: false, l3: true },
      now: 1
    }
  );
  const safe = await scanSourceFile(
    {
      filePath: "orders.py",
      languageId: "python",
      text: `
@app.post("/orders")
def get_order():
    order_id = request.json["order_id"]
    try:
        return cursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    except DatabaseError:
        return {"error": "database unavailable"}, 503
`
    },
    {
      packageVerification: "off",
      detectionLayers: { l1: false, l2: false, l3: true },
      now: 1
    }
  );

  const unsafeRuleIds = new Set(unsafe.findings.map((finding) => finding.detection_rule));
  const safeRuleIds = new Set(safe.findings.map((finding) => finding.detection_rule));
  assert.equal(unsafeRuleIds.has("l3_missing_parameterized_queries"), true);
  assert.equal(unsafeRuleIds.has("l3_missing_error_handling"), true);
  assert.equal(safeRuleIds.has("l3_missing_parameterized_queries"), false);
  assert.equal(safeRuleIds.has("l3_missing_error_handling"), false);
});

test("applies local L3 checks to Django urlpatterns function views", async () => {
  const [unsafe, protectedView] = await Promise.all([
    scanSourceFile(
      {
        filePath: "urls.py",
        languageId: "python",
        text: `
from django.urls import path
from django.views.decorators.http import require_POST

urlpatterns = [path("api/admin/users/", create_user)]

@require_POST
def create_user(request):
    email = request.POST["email"]
    return JsonResponse({"email": email})
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    ),
    scanSourceFile(
      {
        filePath: "urls.py",
        languageId: "python",
        text: `
from django.urls import path
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from django.views.decorators.http import require_POST

urlpatterns = [path("api/admin/users/", create_user)]

@login_required
@ratelimit(key="user", rate="10/m", method="POST", block=True)
@require_POST
def create_user(request):
    form = UserForm(request.POST)
    if form.is_valid():
        return JsonResponse({"email": form.cleaned_data["email"]})
    return JsonResponse({"error": "invalid input"}, status=400)
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    )
  ]);

  const unsafeRuleIds = new Set(unsafe.findings.map((finding) => finding.detection_rule));
  const protectedRuleIds = new Set(protectedView.findings.map((finding) => finding.detection_rule));
  assert.equal(unsafeRuleIds.has("l3_missing_authentication"), true);
  assert.equal(unsafeRuleIds.has("l3_missing_rate_limiting"), true);
  assert.equal(unsafeRuleIds.has("l3_missing_input_validation"), true);
  assert.equal(protectedRuleIds.has("l3_missing_authentication"), false);
  assert.equal(protectedRuleIds.has("l3_missing_rate_limiting"), false);
  assert.equal(protectedRuleIds.has("l3_missing_input_validation"), false);
});

test("applies local L3 checks to Django views.py function views without scanning helpers", async () => {
  const [unsafe, protectedView, helper] = await Promise.all([
    scanSourceFile(
      {
        filePath: "views.py",
        languageId: "python",
        text: `
from django.http import JsonResponse
from django.views.decorators.http import require_POST

@require_POST
def create_account(request):
    email = request.POST["email"]
    return JsonResponse({"email": email})
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    ),
    scanSourceFile(
      {
        filePath: "views.py",
        languageId: "python",
        text: `
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django_ratelimit.decorators import ratelimit
from django.views.decorators.http import require_POST

@login_required
@ratelimit(key="user", rate="10/m", method="POST", block=True)
@require_POST
def create_account(request):
    form = AccountForm(request.POST)
    if form.is_valid():
        return JsonResponse({"email": form.cleaned_data["email"]})
    return JsonResponse({"error": "invalid input"}, status=400)
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    ),
    scanSourceFile(
      {
        filePath: "helpers.py",
        languageId: "python",
        text: `
from django.utils.text import slugify

def normalize_request(request):
    return slugify(request.POST["name"])
`
      },
      {
        packageVerification: "off",
        detectionLayers: { l1: false, l2: false, l3: true },
        now: 1
      }
    )
  ]);

  const unsafeRuleIds = new Set(unsafe.findings.map((finding) => finding.detection_rule));
  const protectedRuleIds = new Set(protectedView.findings.map((finding) => finding.detection_rule));
  assert.equal(unsafeRuleIds.has("l3_missing_authentication"), true);
  assert.equal(unsafeRuleIds.has("l3_missing_rate_limiting"), true);
  assert.equal(unsafeRuleIds.has("l3_missing_input_validation"), true);
  assert.equal(protectedRuleIds.has("l3_missing_authentication"), false);
  assert.equal(protectedRuleIds.has("l3_missing_rate_limiting"), false);
  assert.equal(protectedRuleIds.has("l3_missing_input_validation"), false);
  assert.equal(helper.findings.some((finding) => finding.detection_layer === "L3"), false);
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

function packageReference(registry: PackageReference["registry"], packageName: string): PackageReference {
  return {
    registry,
    packageName,
    rawSpecifier: packageName,
    line: 1,
    column: 1,
    endLine: 1,
    endColumn: packageName.length + 1,
    source: "manifest"
  };
}

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

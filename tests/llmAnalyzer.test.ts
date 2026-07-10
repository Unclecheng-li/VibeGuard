import assert from "node:assert/strict";
import test from "node:test";
import {
  getLlmApiKeyFromEnv,
  LlmSemanticAnalyzer,
  llmApiKeyEnvNames,
  parseLlmSecurityFindings
} from "../src/l3/llm";

test("parses LLM security review JSON into L3 findings", () => {
  const source = {
    filePath: "routes.ts",
    languageId: "typescript",
    text: `
app.post("/api/admin/users", (req, res) => {
  res.json({ ok: true });
});
`
  };
  const findings = parseLlmSecurityFindings(
    JSON.stringify({
      findings: [
        {
          ruleId: "missing authentication",
          severity: "high",
          message: "Admin endpoint is missing authentication.",
          evidence: 'app.post("/api/admin/users"',
          suggestion: "Add authentication middleware.",
          line: 2,
          column: 1
        }
      ]
    }),
    source,
    1
  );

  assert.equal(findings.length, 1);
  assert.equal(findings[0].detection_layer, "L3");
  assert.equal(findings[0].detection_rule, "l3_llm_missing_authentication");
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].line, 2);
});

test("creates a reviewable L3 fix only for an exact evidence replacement", () => {
  const source = {
    filePath: "db.ts",
    languageId: "typescript",
    text: 'const query = `SELECT * FROM users WHERE id = ${req.query.id}`;'
  };
  const findings = parseLlmSecurityFindings(
    JSON.stringify({
      findings: [
        {
          ruleId: "parameterized query",
          severity: "high",
          message: "The query interpolates request input.",
          evidence: 'const query = `SELECT * FROM users WHERE id = ${req.query.id}`;',
          suggestion: "Bind the id instead of interpolating it.",
          replacement: 'const query = "SELECT * FROM users WHERE id = ?";'
        },
        {
          ruleId: "unsafe replacement",
          severity: "high",
          message: "This replacement must be rejected.",
          evidence: "missing evidence",
          suggestion: "Review it.",
          replacement: "```typescript\\nmalicious()\\n```"
        },
        {
          ruleId: "diff replacement",
          severity: "high",
          message: "This diff must be rejected.",
          evidence: 'const query = `SELECT * FROM users WHERE id = ${req.query.id}`;',
          suggestion: "Review it.",
          replacement: "--- a/db.ts\\n+++ b/db.ts"
        }
      ]
    }),
    source,
    1
  );

  assert.equal(findings.length, 3);
  assert.deepEqual(findings[0].fix, {
    description: "Review LLM-generated replacement",
    edits: [
      {
        startLine: 1,
        startColumn: 1,
        endLine: 1,
        endColumn: source.text.length + 1,
        newText: 'const query = "SELECT * FROM users WHERE id = ?";'
      }
    ]
  });
  assert.equal(findings[1].fix, undefined);
  assert.equal(findings[2].fix, undefined);
});

test("requests OpenAI-compatible LLM providers and converts response content", async () => {
  let requestedUrl = "";
  let authorization = "";
  let requestBody: unknown;
  const analyzer = new LlmSemanticAnalyzer({
    provider: "deepseek",
    apiKey: "secret-key",
    model: "deepseek-test",
    baseUrl: "https://llm.example/v1",
    fallbackAnalyzer: false,
    fetchImpl: async (url, init) => {
      requestedUrl = String(url);
      authorization = String((init?.headers as Record<string, string>).authorization);
      requestBody = JSON.parse(String(init?.body));
      return response(
        JSON.stringify({
          choices: [
            {
              message: {
                content: JSON.stringify({
                  findings: [
                    {
                      ruleId: "l3_llm_missing_rate_limiting",
                      severity: "medium",
                      message: "Login endpoint has no rate limiting.",
                      evidence: 'app.post("/login"',
                      suggestion: "Add a rate limiter."
                    }
                  ]
                })
              }
            }
          ]
        })
      );
    }
  });

  const findings = await analyzer.analyze(
    {
      filePath: "routes.ts",
      languageId: "typescript",
      text: 'app.post("/login", (req, res) => res.send("ok"));'
    },
    1
  );

  assert.equal(requestedUrl, "https://llm.example/v1/chat/completions");
  assert.equal(authorization, "Bearer secret-key");
  assert.equal((requestBody as { model: string }).model, "deepseek-test");
  assert.match(JSON.stringify(requestBody), /replacement/);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detection_rule, "l3_llm_missing_rate_limiting");
});

test("falls back to local L3 analysis when remote provider has no API key", async () => {
  const analyzer = new LlmSemanticAnalyzer({
    provider: "openai"
  });

  const findings = await analyzer.analyze(
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
    1
  );

  assert.equal(findings.some((finding) => finding.detection_rule === "l3_missing_authentication"), true);
});

test("reads provider-specific LLM API keys from environment variables", () => {
  const previous = process.env.DEEPSEEK_API_KEY;
  process.env.DEEPSEEK_API_KEY = "deepseek-key";
  try {
    assert.deepEqual(llmApiKeyEnvNames("openai"), ["OPENAI_API_KEY", "VIBEGUARD_LLM_API_KEY"]);
    assert.equal(getLlmApiKeyFromEnv("deepseek"), "deepseek-key");
    assert.equal(getLlmApiKeyFromEnv("local"), undefined);
  } finally {
    if (previous === undefined) {
      delete process.env.DEEPSEEK_API_KEY;
    } else {
      process.env.DEEPSEEK_API_KEY = previous;
    }
  }
});

function response(body: string): Response {
  return {
    ok: true,
    status: 200,
    text: async () => body
  } as Response;
}

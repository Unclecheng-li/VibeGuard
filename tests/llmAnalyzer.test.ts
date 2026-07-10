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

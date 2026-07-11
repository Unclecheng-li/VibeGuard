import assert from "node:assert/strict";
import test from "node:test";
import {
  buildLlmSecurityReviewPrompt,
  defaultLlmBaseUrl,
  defaultLlmModel,
  getLlmApiKeyFromEnv,
  LlmSemanticAnalyzer,
  llmApiKeyEnvNames,
  parseLlmSecurityFindings
} from "../src/l3/llm";
import { buildSecurityReviewContext } from "../src/l3/analyzer";

test("adds detected framework, function, and route context to L3 prompts", () => {
  const source = {
    filePath: "orders.ts",
    languageId: "typescript",
    text: `
import express from "express";
const app = express();
app.post("/orders", async function createOrder(req, res) {
  return res.json({ ok: true });
});
`
  };
  const context = buildSecurityReviewContext(source);
  const prompt = buildLlmSecurityReviewPrompt(source);

  assert.equal(context.framework, "Express");
  assert.deepEqual(context.functionNames, ["createOrder"]);
  assert.deepEqual(context.routes, ["POST /orders"]);
  assert.match(prompt, /Framework: Express/);
  assert.match(prompt, /Function candidates: createOrder/);
  assert.match(prompt, /Route candidates: POST \/orders/);
});

test("detects FastAPI context for L3 prompts", () => {
  const context = buildSecurityReviewContext({
    filePath: "orders.py",
    languageId: "python",
    text: `
from fastapi import FastAPI
app = FastAPI()
@app.post("/orders")
async def create_order():
    return {"ok": True}
`
  });

  assert.equal(context.framework, "FastAPI");
  assert.deepEqual(context.functionNames, ["create_order"]);
  assert.deepEqual(context.routes, ["POST /orders"]);
});

test("redacts likely secrets from prompts sent to remote LLM providers", () => {
  const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
  const privateKeyMaterial = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";
  const source = {
    filePath: "settings.ts",
    languageId: "typescript",
    text: `const apiKey = "${secret}";\nconst privateKey = \`-----BEGIN PRIVATE KEY-----\n${privateKeyMaterial}\n-----END PRIVATE KEY-----\`;\napp.get("/health", (_, res) => res.send("ok"));`
  };

  const remotePrompt = buildLlmSecurityReviewPrompt(source);
  const localPrompt = buildLlmSecurityReviewPrompt(source, false);

  assert.equal(remotePrompt.includes(secret), false);
  assert.equal(remotePrompt.includes(privateKeyMaterial), false);
  assert.match(remotePrompt, /VIBEGUARD_REDACTED_SECRET/);
  assert.match(remotePrompt, /Do not infer, report, or replace those placeholders/);
  assert.equal(localPrompt.includes(secret), true);
});

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
  let redirect: RequestRedirect | undefined;
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
      redirect = init?.redirect;
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
  assert.equal(redirect, "error");
  assert.equal((requestBody as { model: string }).model, "deepseek-test");
  assert.match(JSON.stringify(requestBody), /replacement/);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detection_rule, "l3_llm_missing_rate_limiting");
});

test("does not send hardcoded secrets to remote L3 providers", async () => {
  const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
  let requestBody = "";
  const analyzer = new LlmSemanticAnalyzer({
    provider: "openai",
    apiKey: "secret-key",
    baseUrl: "https://llm.example/v1",
    fallbackAnalyzer: false,
    fetchImpl: async (_url, init) => {
      requestBody = String(init?.body ?? "");
      return response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ findings: [] }) } }] }));
    }
  });

  await analyzer.analyze(
    { filePath: "settings.ts", languageId: "typescript", text: `const apiKey = "${secret}";` },
    1
  );

  assert.equal(requestBody.includes(secret), false);
  assert.match(requestBody, /VIBEGUARD_REDACTED_SECRET/);
});

test("uses the Pro provider's OpenAI-compatible hosted endpoint", async () => {
  let requestedUrl = "";
  let authorization = "";
  const analyzer = new LlmSemanticAnalyzer({
    provider: "vibeguard",
    apiKey: "pro-credential",
    baseUrl: "https://pro.example.test/v1",
    fallbackAnalyzer: false,
    fetchImpl: async (url, init) => {
      requestedUrl = String(url);
      authorization = String((init?.headers as Record<string, string>).authorization);
      return response(
        JSON.stringify({
          choices: [{ message: { content: JSON.stringify({ findings: [] }) } }]
        })
      );
    }
  });

  const findings = await analyzer.analyze({ filePath: "app.ts", text: "const ok = true;" }, 1);

  assert.equal(requestedUrl, "https://pro.example.test/v1/chat/completions");
  assert.equal(authorization, "Bearer pro-credential");
  assert.deepEqual(findings, []);
});

test("does not send LLM credentials or source to insecure remote endpoints", async () => {
  let requested = false;
  const analyzer = new LlmSemanticAnalyzer({
    provider: "openai",
    apiKey: "secret-key",
    baseUrl: "http://llm.example.test/v1",
    fallbackAnalyzer: false,
    fetchImpl: async () => {
      requested = true;
      throw new Error("should not run");
    }
  });

  const findings = await analyzer.analyze({ filePath: "app.ts", text: "const ok = true;" }, 1);

  assert.equal(requested, false);
  assert.deepEqual(findings, []);
});

test("permits a local Ollama endpoint on loopback HTTP", async () => {
  let requestedUrl = "";
  const analyzer = new LlmSemanticAnalyzer({
    provider: "local",
    baseUrl: "http://127.0.0.1:11434",
    fallbackAnalyzer: false,
    fetchImpl: async (url) => {
      requestedUrl = String(url);
      return response(JSON.stringify({ message: { content: JSON.stringify({ findings: [] }) } }));
    }
  });

  const findings = await analyzer.analyze({ filePath: "app.ts", text: "const ok = true;" }, 1);

  assert.equal(requestedUrl, "http://127.0.0.1:11434/api/chat");
  assert.deepEqual(findings, []);
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
  const previousPro = process.env.VIBEGUARD_PRO_API_KEY;
  process.env.DEEPSEEK_API_KEY = "deepseek-key";
  process.env.VIBEGUARD_PRO_API_KEY = "pro-key";
  try {
    assert.deepEqual(llmApiKeyEnvNames("openai"), ["OPENAI_API_KEY", "VIBEGUARD_LLM_API_KEY"]);
    assert.deepEqual(llmApiKeyEnvNames("vibeguard"), ["VIBEGUARD_PRO_API_KEY"]);
    assert.equal(getLlmApiKeyFromEnv("deepseek"), "deepseek-key");
    assert.equal(getLlmApiKeyFromEnv("vibeguard"), "pro-key");
    assert.equal(getLlmApiKeyFromEnv("local"), undefined);
    assert.equal(defaultLlmModel("vibeguard"), "vibeguard-security-pro");
    assert.match(defaultLlmBaseUrl("vibeguard"), /^https:\/\//);
  } finally {
    if (previous === undefined) {
      delete process.env.DEEPSEEK_API_KEY;
    } else {
      process.env.DEEPSEEK_API_KEY = previous;
    }
    if (previousPro === undefined) {
      delete process.env.VIBEGUARD_PRO_API_KEY;
    } else {
      process.env.VIBEGUARD_PRO_API_KEY = previousPro;
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

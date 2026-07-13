import assert from "node:assert/strict";
import test from "node:test";
import { LlmSemanticAnalyzer } from "../src/l3/llm";
import { runManualL3Review } from "../src/l3/manualReview";

const source = {
  filePath: "routes.ts",
  languageId: "typescript",
  text: 'app.post("/login", (req, res) => res.send("ok"));'
};

test("manual L3 review requires explicit remote approval before creating a request", async () => {
  let requested = false;
  const analyzer = new LlmSemanticAnalyzer({
    provider: "openai",
    apiKey: "secret",
    fallbackAnalyzer: false,
    fetchImpl: async () => {
      requested = true;
      throw new Error("must not run");
    }
  });

  const outcome = await runManualL3Review({
    source,
    provider: "openai",
    analyzer,
    remoteApproved: false,
    timestamp: 1
  });

  assert.equal(outcome.status, "consentRequired");
  assert.equal(outcome.errorCode, "consentRequired");
  assert.equal(requested, false);
});

test("manual L3 review preserves remote usage while retaining scanner finding filtering", async () => {
  const analyzer = new LlmSemanticAnalyzer({
    provider: "openai",
    apiKey: "secret",
    model: "review-model",
    fallbackAnalyzer: false,
    fetchImpl: async () =>
      response(
        JSON.stringify({
          usage: { prompt_tokens: 31, completion_tokens: 7 },
          choices: [
            {
              message: {
                content: JSON.stringify({
                  findings: [
                    {
                      ruleId: "missing authentication",
                      severity: "high",
                      message: "The login route has no authentication.",
                      evidence: 'app.post("/login"',
                      line: 1,
                      column: 1
                    }
                  ]
                })
              }
            }
          ]
        })
      )
  });

  const outcome = await runManualL3Review({
    source,
    provider: "openai",
    analyzer,
    remoteApproved: true,
    timestamp: 1
  });

  assert.equal(outcome.status, "remote");
  assert.deepEqual(outcome.usage, {
    provider: "openai",
    model: "review-model",
    tokensIn: 31,
    tokensOut: 7
  });
  assert.equal(outcome.findings.length, 1);
  assert.equal(outcome.findings[0].detection_layer, "L3");
});

test("cancelling an LLM review does not run the local fallback", async () => {
  const controller = new AbortController();
  const analyzer = new LlmSemanticAnalyzer({
    provider: "openai",
    apiKey: "secret",
    signal: controller.signal,
    fetchImpl: async (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      })
  });
  controller.abort();

  const outcome = await analyzer.review(source, 1);

  assert.equal(outcome.status, "cancelled");
  assert.deepEqual(outcome.findings, []);
});

function response(body: string): Response {
  return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
}

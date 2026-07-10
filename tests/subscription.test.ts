import assert from "node:assert/strict";
import test from "node:test";
import {
  getProApiKeyFromEnv,
  getProSubscriptionStatus,
  parseProSubscriptionStatus,
  proApiEndpoint
} from "../src/subscription";

test("reads the Pro credential only from the designated environment variable", () => {
  const previous = process.env.VIBEGUARD_PRO_API_KEY;
  process.env.VIBEGUARD_PRO_API_KEY = "pro-secret";
  try {
    assert.equal(getProApiKeyFromEnv(), "pro-secret");
  } finally {
    if (previous === undefined) {
      delete process.env.VIBEGUARD_PRO_API_KEY;
    } else {
      process.env.VIBEGUARD_PRO_API_KEY = previous;
    }
  }
});

test("reports a missing Pro credential without making a network request", async () => {
  let requested = false;
  const status = await getProSubscriptionStatus({
    fetchImpl: async () => {
      requested = true;
      throw new Error("should not run");
    }
  });

  assert.equal(requested, false);
  assert.deepEqual(status, {
    active: false,
    plan: "free",
    state: "inactive",
    features: [],
    reason: "missing_credential"
  });
});

test("queries the hosted account usage endpoint and normalizes the subscription payload", async () => {
  let requestedUrl = "";
  let authorization = "";
  const status = await getProSubscriptionStatus({
    apiKey: "pro-secret",
    baseUrl: "https://pro.example.test/v1",
    fetchImpl: async (url, init) => {
      requestedUrl = String(url);
      authorization = String((init?.headers as Record<string, string>).authorization);
      return response({
        plan: "team",
        status: "active",
        features: ["official_llm", "batch_fixes", "official_llm"],
        usage: {
          l3_requests: {
            used: 12,
            limit: 1000,
            reset_at: "2026-08-01T00:00:00.000Z"
          }
        }
      });
    }
  });

  assert.equal(requestedUrl, "https://pro.example.test/v1/account/usage");
  assert.equal(authorization, "Bearer pro-secret");
  assert.deepEqual(status, {
    active: true,
    plan: "team",
    state: "active",
    features: ["official_llm", "batch_fixes"],
    l3Requests: {
      used: 12,
      limit: 1000,
      resetAt: "2026-08-01T00:00:00.000Z"
    }
  });
});

test("rejects insecure hosted endpoints and unknown subscription values", () => {
  assert.throws(() => proApiEndpoint("http://pro.example.test/v1", "/account/usage"), /HTTPS/);
  assert.throws(() => proApiEndpoint("https://user:pass@pro.example.test/v1", "/account/usage"), /credentials/);
  assert.throws(() => proApiEndpoint("https://pro.example.test/v1?debug=true", "/account/usage"), /query parameters/);
  assert.equal(proApiEndpoint("http://localhost:8788/v1", "/account/usage"), "http://localhost:8788/v1/account/usage");
  assert.deepEqual(parseProSubscriptionStatus({ plan: "unknown", status: "unknown", features: ["official_llm", 42] }), {
    active: false,
    plan: "free",
    state: "inactive",
    features: ["official_llm"]
  });
});

function response(value: unknown): Response {
  return {
    ok: true,
    status: 200,
    text: async () => JSON.stringify(value)
  } as Response;
}

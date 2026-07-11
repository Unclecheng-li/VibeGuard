import assert from "node:assert/strict";
import test from "node:test";
import {
  cliFalsePositiveTelemetryEvent,
  falsePositiveTelemetryEvent,
  isFalsePositiveDismissalReason,
  parseFalsePositiveTelemetryEvent,
  reportFalsePositiveTelemetry
} from "../src/telemetry";
import type { Finding } from "../src/types";

test("builds anonymous false-positive events without source or identifier fields", () => {
  const event = falsePositiveTelemetryEvent(finding(), "vscode", "line");

  assert.deepEqual(event, {
    schemaVersion: 1,
    event: "false_positive_dismissal",
    source: "vscode",
    scope: "line",
    ruleFingerprint: "de464ac68e03c73bda9a4148",
    findingType: "sql_injection",
    detectionLayer: "L2",
    severity: "high"
  });
  assert.equal(JSON.stringify(event).includes("app.ts"), false);
  assert.equal(JSON.stringify(event).includes("SELECT"), false);
  assert.equal(JSON.stringify(event).includes("vg_secret"), false);
  assert.equal(JSON.stringify(event).includes("sast_sql_template_interpolation"), false);
});

test("recognizes only standardized false-positive dismissal reasons", () => {
  assert.equal(isFalsePositiveDismissalReason("False positive (line ignore)"), true);
  assert.equal(isFalsePositiveDismissalReason("false_positive: reviewed"), true);
  assert.equal(isFalsePositiveDismissalReason("Not an issue"), false);
  assert.equal(isFalsePositiveDismissalReason("False positive-ish"), false);
});

test("accepts only the privacy-minimized telemetry collector schema", () => {
  const event = cliFalsePositiveTelemetryEvent("rule", "cli", "global");
  assert.deepEqual(parseFalsePositiveTelemetryEvent(event), event);
  assert.throws(
    () => parseFalsePositiveTelemetryEvent({ ...event, file: "/private/workspace/app.ts" }),
    /unsupported fields/
  );
  assert.throws(() => parseFalsePositiveTelemetryEvent({ ...event, ruleFingerprint: "not-a-fingerprint" }), /fingerprint/);
});

test("does not make a request when telemetry is disabled", async () => {
  let requests = 0;
  const result = await reportFalsePositiveTelemetry({
    enabled: false,
    event: cliFalsePositiveTelemetryEvent("rule", "cli", "global"),
    fetchImpl: async () => {
      requests += 1;
      return new Response(null, { status: 204 });
    }
  });

  assert.deepEqual(result, { attempted: false, sent: false });
  assert.equal(requests, 0);
});

test("posts only the anonymous event to a secure configured endpoint", async () => {
  let url = "";
  let init: RequestInit | undefined;
  const event = cliFalsePositiveTelemetryEvent("rule", "cli", "global");
  const result = await reportFalsePositiveTelemetry({
    enabled: true,
    event,
    endpoint: "https://telemetry.example.test/feedback",
    fetchImpl: async (value, request) => {
      url = String(value);
      init = request;
      return new Response(null, { status: 204 });
    }
  });

  assert.deepEqual(result, { attempted: true, sent: true });
  assert.equal(url, "https://telemetry.example.test/feedback");
  assert.equal(init?.method, "POST");
  assert.equal(init?.redirect, "error");
  assert.equal(init?.body, JSON.stringify(event));
});

test("rejects insecure telemetry endpoints without making a request", async () => {
  let requests = 0;
  const result = await reportFalsePositiveTelemetry({
    enabled: true,
    event: cliFalsePositiveTelemetryEvent("rule", "cli", "global"),
    endpoint: "http://telemetry.example.test/feedback",
    fetchImpl: async () => {
      requests += 1;
      return new Response(null, { status: 204 });
    }
  });

  assert.deepEqual(result, { attempted: false, sent: false });
  assert.equal(requests, 0);
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "vg_secret",
    type: "sql_injection",
    severity: "high",
    message: "Unsafe query",
    file: "app.ts",
    line: 1,
    column: 1,
    evidence: "SELECT ${id}",
    detection_layer: "L2",
    detection_rule: "sast_sql_template_interpolation",
    timestamp: 1,
    dismissed: false,
    ...overrides
  };
}

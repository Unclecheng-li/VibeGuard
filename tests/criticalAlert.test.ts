import assert from "node:assert/strict";
import test from "node:test";
import { criticalAlertMessage } from "../src/criticalAlert";
import type { Finding } from "../src/types";

test("critical package alerts explain the slopsquatting risk", () => {
  assert.match(criticalAlertMessage(finding({ type: "hallucinated_package" })), /slopsquatting risk/i);
  assert.match(criticalAlertMessage(finding({ type: "hallucinated_package" })), /attacker could register/i);
});

test("other critical alerts preserve their concise finding message", () => {
  assert.equal(criticalAlertMessage(finding()), "VibeGuard: Sensitive value is hardcoded.");
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding",
    type: "hardcoded_secret",
    severity: "critical",
    message: "Sensitive value is hardcoded.",
    file: "/repo/app.ts",
    line: 1,
    column: 1,
    evidence: "secret",
    detection_layer: "L1",
    detection_rule: "hardcoded_secret",
    timestamp: 1,
    dismissed: false,
    ...overrides
  };
}

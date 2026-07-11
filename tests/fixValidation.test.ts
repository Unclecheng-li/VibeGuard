import assert from "node:assert/strict";
import test from "node:test";
import { redactedSecretFixStillMatchesSource } from "../src/fixValidation";
import { detectSecrets } from "../src/rules/secrets";

const original = 'const apiKey = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";';

test("validates a redacted secret finding through its regenerated safe fix", () => {
  const finding = detectSecrets(original, "app.ts", 1)[0];

  assert.ok(finding?.fix);
  assert.doesNotMatch(finding?.evidence ?? "", /aaaaaaaaaaaaaaaa/);
  assert.equal(redactedSecretFixStillMatchesSource(finding, finding.fix, original), true);
});

test("rejects a redacted secret fix after its target range or secret finding changes", () => {
  const finding = detectSecrets(original, "app.ts", 1)[0];

  assert.ok(finding?.fix);
  assert.equal(
    redactedSecretFixStillMatchesSource(
      finding,
      finding.fix,
      'const apiKey = "sk-proj-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";'
    ),
    false
  );
  assert.equal(redactedSecretFixStillMatchesSource(finding, finding.fix, 'const apiKey = process.env.API_KEY ?? "";'), false);
});

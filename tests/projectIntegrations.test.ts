import assert from "node:assert/strict";
import test from "node:test";
import { formatProjectIntegrationsDashboard } from "../src/findings/projectIntegrations";

test("formats an interactive project integration page without client-side token persistence", () => {
  const html = formatProjectIntegrationsDashboard({ title: "Security Team" });

  assert.match(html, /Security Team/);
  assert.match(html, /Create Credential/);
  assert.match(html, /Project Credentials/);
  assert.match(html, /GitHub Action/);
  assert.match(html, /request\("\/api\/projects"/);
  assert.match(html, /Rotate this project credential/);
  assert.match(html, /navigator\.clipboard\.writeText/);
  assert.match(html, /findings_project/);
  assert.match(html, /findings_endpoint/);
  assert.match(html, /findings_token_env/);
  assert.match(html, /findings_rules_endpoint/);
  assert.match(html, /workflowSnippet\(credential\.project\)/);
  assert.match(html, /secrets\.VIBEGUARD_FINDINGS_INGEST_TOKEN/);
  assert.match(html, /Project Custom Rules/);
  assert.match(html, /request\("\/api\/project-rules"/);
  assert.match(html, /Insert template/);
  assert.equal(html.includes("localStorage"), false);
  assert.equal(html.includes("sessionStorage"), false);
  assert.equal(html.includes("innerHTML"), false);
});

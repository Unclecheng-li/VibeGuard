import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

test("GitHub Action exposes findings dashboard and compliance report inputs and outputs", async () => {
  const raw = await fs.readFile("action.yml", "utf8");
  const manifest = parse(raw) as {
    inputs: Record<string, { default?: string; description?: string }>;
    outputs: Record<string, { value?: string }>;
    runs: {
      steps: Array<{ id?: string; name?: string; uses?: string; run?: string; with?: Record<string, string | number> }>;
    };
  };
  const runStep = manifest.runs.steps.find((step) => step.id === "vibeguard");
  const nodeSetupStep = manifest.runs.steps.find((step) => step.name === "Set up Node.js 22");

  assert.equal(manifest.inputs.dashboard.default, "false");
  assert.equal(manifest.inputs.dashboard_path.default, "");
  assert.equal(manifest.inputs.dashboard_days.default, "30");
  assert.equal(manifest.inputs.dashboard_top.default, "10");
  assert.equal(manifest.inputs.compliance.default, "false");
  assert.equal(manifest.inputs.compliance_framework.default, "all");
  assert.equal(manifest.inputs.compliance_days.default, "90");
  assert.equal(manifest.inputs.pr_review_comments.default, "false");
  assert.equal(manifest.inputs.pr_review_comment_limit.default, "20");
  assert.equal(manifest.inputs.findings_endpoint.default, "");
  assert.equal(manifest.inputs.findings_project.default, "");
  assert.equal(manifest.inputs.findings_token_env.default, "VIBEGUARD_FINDINGS_INGEST_TOKEN");
  assert.equal(manifest.inputs.findings_rules_endpoint.default, "");
  assert.equal(manifest.inputs.findings_rules_required.default, "false");
  assert.equal(manifest.inputs.findings_upload_required.default, "false");
  assert.match(manifest.inputs.llm_provider.description ?? "", /vibeguard/);
  assert.equal(manifest.outputs.dashboard_path.value, "${{ steps.vibeguard.outputs.dashboard_path }}");
  assert.equal(manifest.outputs.compliance_path.value, "${{ steps.vibeguard.outputs.compliance_path }}");
  assert.equal(nodeSetupStep?.uses, "actions/setup-node@v5");
  assert.equal(nodeSetupStep?.with?.["node-version"], 22);
  assert.equal(nodeSetupStep?.with?.["cache-dependency-path"], "${{ github.action_path }}/package-lock.json");
  assert.ok(runStep);
  assert.match(runStep.run ?? "", /findings dashboard/);
  assert.match(runStep.run ?? "", /store_findings/);
  assert.match(runStep.run ?? "", /GITHUB_OUTPUT/);
  assert.match(runStep.run ?? "", /findings compliance/);
  assert.match(runStep.run ?? "", /create-pr-review-payload/);
  assert.match(runStep.run ?? "", /pulls\/\$pr_number\/reviews/);
  assert.match(runStep.run ?? "", /--findings-endpoint/);
  assert.match(runStep.run ?? "", /--findings-project/);
  assert.match(runStep.run ?? "", /findings_rules_endpoint/);
  assert.match(runStep.run ?? "", /--custom-rules/);
  assert.match(runStep.run ?? "", /findings_rules_required/);
  assert.match(
    runStep.run ?? "",
    /rules_status"\s*=\s*"404"\s*\]\s*&&\s*\[\s*"\$\{\{\s*inputs\.findings_rules_required\s*\}\}"\s*!=\s*"true"/
  );
  assert.match(runStep.run ?? "", /--findings-upload-required/);
});

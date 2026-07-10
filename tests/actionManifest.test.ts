import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

test("GitHub Action exposes findings dashboard export inputs and output", async () => {
  const raw = await fs.readFile("action.yml", "utf8");
  const manifest = parse(raw) as {
    inputs: Record<string, { default?: string; description?: string }>;
    outputs: Record<string, { value?: string }>;
    runs: {
      steps: Array<{ id?: string; run?: string }>;
    };
  };
  const runStep = manifest.runs.steps.find((step) => step.id === "vibeguard");

  assert.equal(manifest.inputs.dashboard.default, "false");
  assert.equal(manifest.inputs.dashboard_path.default, "");
  assert.equal(manifest.inputs.dashboard_days.default, "30");
  assert.equal(manifest.inputs.dashboard_top.default, "10");
  assert.equal(manifest.outputs.dashboard_path.value, "${{ steps.vibeguard.outputs.dashboard_path }}");
  assert.ok(runStep);
  assert.match(runStep.run ?? "", /findings dashboard/);
  assert.match(runStep.run ?? "", /store_findings/);
  assert.match(runStep.run ?? "", /GITHUB_OUTPUT/);
});

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

test("Marketplace release workflow validates versions, publishes only tags, and uses secret-backed tokens", async () => {
  const raw = await fs.readFile(".github/workflows/release.yml", "utf8");
  const workflow = parse(raw) as {
    on: { push: { tags: string[] }; workflow_dispatch: Record<string, never> };
    jobs: Record<string, { steps?: Array<{ name?: string; if?: string; run?: string; env?: Record<string, string> }> }>;
  };

  assert.deepEqual(workflow.on.push.tags, ["v*"]);
  assert.ok("workflow_dispatch" in workflow.on);
  const vscodeSteps = workflow.jobs.vscode.steps ?? [];
  const jetbrainsSteps = workflow.jobs.jetbrains.steps ?? [];
  const vscodePublish = vscodeSteps.find((step) => step.name === "Publish VSCode extension");
  const jetbrainsPublish = jetbrainsSteps.find((step) => step.name === "Publish JetBrains plugin");
  assert.equal(vscodePublish?.if, "github.event_name == 'push'");
  assert.equal(jetbrainsPublish?.if, "github.event_name == 'push'");
  assert.equal(vscodePublish?.env?.VSCE_PAT, "${{ secrets.VSCE_PAT }}");
  assert.equal(jetbrainsPublish?.env?.JETBRAINS_MARKETPLACE_TOKEN, "${{ secrets.JETBRAINS_MARKETPLACE_TOKEN }}");
  assert.match(vscodePublish?.run ?? "", /--packagePath/);
  assert.match(jetbrainsPublish?.run ?? "", /publishPlugin/);

  const gradle = await fs.readFile("jetbrains/build.gradle.kts", "utf8");
  assert.match(gradle, /publishing\s*\{/);
  assert.match(gradle, /JETBRAINS_MARKETPLACE_TOKEN/);
});

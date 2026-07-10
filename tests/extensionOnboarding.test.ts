import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode extension exposes first-run cold-start onboarding", async () => {
  const source = await fs.readFile("src/extension.ts", "utf8");

  assert.match(source, /firstRunOnboardingKey/);
  assert.match(source, /maybeShowFirstRunOnboarding/);
  assert.match(source, /globalState\.update\(firstRunOnboardingKey, true\)/);
  assert.match(source, /Package-name cache sync runs in the background/);
  assert.match(source, /Sync Now/);
  assert.match(source, /workbench\.action\.openSettings/);
});

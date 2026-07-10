import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode manifest exposes dashboard, batch-fix, and Pro subscription commands", async () => {
  const manifest = JSON.parse(await fs.readFile("package.json", "utf8")) as {
    activationEvents: string[];
    contributes: {
      commands: Array<{ command: string; title: string }>;
    };
  };
  const command = manifest.contributes.commands.find((item) => item.command === "vibeguard.exportDashboard");
  const batchFixCommand = manifest.contributes.commands.find((item) => item.command === "vibeguard.applyAllSafeFixes");
  const subscriptionCommand = manifest.contributes.commands.find((item) => item.command === "vibeguard.showSubscriptionStatus");

  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.exportDashboard"));
  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.applyAllSafeFixes"));
  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.showSubscriptionStatus"));
  assert.ok(command);
  assert.equal(command.title, "VibeGuard: Export Findings Dashboard");
  assert.equal(batchFixCommand?.title, "VibeGuard: Apply All Safe Fixes in Current File");
  assert.equal(subscriptionCommand?.title, "VibeGuard: Show Pro Subscription Status");
});

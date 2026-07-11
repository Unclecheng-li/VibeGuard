import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode manifest exposes dashboard, batch-fix, and Pro subscription commands", async () => {
  const [manifestRaw, vscodeIgnore] = await Promise.all([
    fs.readFile("package.json", "utf8"),
    fs.readFile(".vscodeignore", "utf8")
  ]);
  const manifest = JSON.parse(manifestRaw) as {
    activationEvents: string[];
    contributes: {
      commands: Array<{ command: string; title: string }>;
      menus: {
        "view/item/context": Array<{ command: string; when: string }>;
      };
      configuration: {
        properties: Record<string, { default?: unknown }>;
      };
    };
  };
  const command = manifest.contributes.commands.find((item) => item.command === "vibeguard.exportDashboard");
  const batchFixCommand = manifest.contributes.commands.find((item) => item.command === "vibeguard.applyAllSafeFixes");
  const proBatchFixCommand = manifest.contributes.commands.find((item) => item.command === "vibeguard.applyAllProFixes");
  const findingFixCommand = manifest.contributes.commands.find((item) => item.command === "vibeguard.applyFindingFix");
  const subscriptionCommand = manifest.contributes.commands.find((item) => item.command === "vibeguard.showSubscriptionStatus");
  const findingFixMenu = manifest.contributes.menus["view/item/context"].find(
    (item) => item.command === "vibeguard.applyFindingFix"
  );

  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.exportDashboard"));
  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.applyAllSafeFixes"));
  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.applyAllProFixes"));
  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.applyFindingFix"));
  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.showSubscriptionStatus"));
  assert.ok(command);
  assert.equal(command.title, "VibeGuard: Export Findings Dashboard");
  assert.equal(batchFixCommand?.title, "VibeGuard: Apply All Safe Fixes in Current File");
  assert.equal(proBatchFixCommand?.title, "VibeGuard: Review and Apply All Pro Fixes in Current File");
  assert.equal(findingFixCommand?.title, "VibeGuard: Apply Finding Fix");
  assert.equal(findingFixMenu?.when, "view == vibeguardFindings && viewItem == vibeguardFindingFixable");
  assert.equal(subscriptionCommand?.title, "VibeGuard: Show Pro Subscription Status");
  assert.equal(manifest.contributes.configuration.properties["vibeguard.packageVerification"]?.default, "remote");
  assert.match(vscodeIgnore, /^deploy\/\*\*$/m);
});

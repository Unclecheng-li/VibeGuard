import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

test("VSCode manifest exposes the findings dashboard export command", async () => {
  const manifest = JSON.parse(await fs.readFile("package.json", "utf8")) as {
    activationEvents: string[];
    contributes: {
      commands: Array<{ command: string; title: string }>;
    };
  };
  const command = manifest.contributes.commands.find((item) => item.command === "vibeguard.exportDashboard");

  assert.ok(manifest.activationEvents.includes("onCommand:vibeguard.exportDashboard"));
  assert.ok(command);
  assert.equal(command.title, "VibeGuard: Export Findings Dashboard");
});

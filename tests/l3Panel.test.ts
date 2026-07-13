import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import { l3PanelHtml } from "../src/panel/l3PanelHtml";
import { parsePanelRequest } from "../src/panel/l3PanelTypes";

test("L3 panel accepts only the documented message schema", () => {
  assert.deepEqual(parsePanelRequest({ type: "scan" }), { type: "scan" });
  assert.deepEqual(parsePanelRequest({ type: "ignoreFinding", findingId: "finding-1", scope: "line" }), {
    type: "ignoreFinding",
    findingId: "finding-1",
    scope: "line"
  });
  assert.equal(parsePanelRequest({ type: "ignoreFinding", findingId: "finding-1", scope: "workspace" }), undefined);
  assert.equal(parsePanelRequest({ type: "openFinding", findingId: "" }), undefined);
  assert.equal(parsePanelRequest({ type: "runArbitraryCommand", command: "rm -rf" }), undefined);
});

test("L3 panel HTML uses a restrictive CSP and text-only finding rendering", () => {
  const html = l3PanelHtml({} as never, "testnonce");

  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-testnonce'/);
  assert.match(html, /style-src 'nonce-testnonce'/);
  assert.match(html, /textContent = finding\.message/);
  assert.equal(html.includes("innerHTML"), false);
  assert.equal(html.includes("http://"), false);
  assert.equal(html.includes("https://"), false);
});

test("VSCode registers the AI Deep Scan panel and preserves L1/L2 while replacing L3", async () => {
  const [extension, manifest, provider, packageScript] = await Promise.all([
    fs.readFile("src/extension.ts", "utf8"),
    fs.readFile("package.json", "utf8"),
    fs.readFile("src/panel/l3PanelProvider.ts", "utf8"),
    fs.readFile("scripts/package-vsix.js", "utf8")
  ]);
  const packageJson = JSON.parse(manifest) as {
    activationEvents: string[];
    contributes: {
      commands: Array<{ command: string }>;
      views: Record<string, Array<{ id: string; type?: string }>>;
      viewsContainers: { activitybar: Array<{ id: string; icon: string }> };
    };
  };

  assert.match(extension, /registerWebviewViewProvider\("vibeguardL3Panel", l3Panel\)/);
  assert.match(extension, /runManualL3Review/);
  assert.match(extension, /mergeFindingsForExecutedLayers\(existing, outcome\.findings, \{ l3: true \}\)/);
  assert.match(extension, /l3Panel\.cancelDocument\(document\)/);
  assert.match(extension, /async function scanWorkspace\(\)[\s\S]{0,1000}includeL3: false/);
  assert.match(provider, /private preparingScan = false/);
  assert.match(provider, /cancelDocument\(document: vscode\.TextDocument\)/);
  assert.equal(packageJson.activationEvents.includes("onView:vibeguardL3Panel"), true);
  assert.equal(packageJson.contributes.commands.some((command) => command.command === "vibeguard.scanWithAi"), true);
  assert.equal(packageJson.contributes.views.vibeguard.some((view) => view.id === "vibeguardL3Panel" && view.type === "webview"), true);
  const activityBar = packageJson.contributes.viewsContainers.activitybar.find((container) => container.id === "vibeguard");
  assert.equal(activityBar?.icon, "$(shield)");
  assert.match(packageScript, /vibeguard-\$\{version\}\.vsix/);
  assert.match(packageScript, /process\.platform === "win32" \? "npm\.cmd" : "npm"/);
  assert.match(packageScript, /shell: process\.platform === "win32"/);
});

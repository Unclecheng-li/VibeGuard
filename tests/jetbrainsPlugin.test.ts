import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(__dirname, "../..");

test("JetBrains plugin packages the Node LSP, exposes the VibeGuard ToolWindow, and supports an opt-in native preview", async () => {
  const [buildFile, pluginXml, provider, descriptor, bridge, panel] = await Promise.all([
    readJetBrainsFile("build.gradle.kts"),
    readJetBrainsFile("src/main/resources/META-INF/plugin.xml"),
    readJetBrainsFile("src/main/java/dev/vibeguard/jetbrains/VibeGuardLspServerSupportProvider.java"),
    readJetBrainsFile("src/main/java/dev/vibeguard/jetbrains/VibeGuardLspServerDescriptor.java"),
    readJetBrainsFile("src/main/java/dev/vibeguard/jetbrains/lsp/VibeGuardLspBridge.java"),
    readJetBrainsFile("src/main/java/dev/vibeguard/jetbrains/ui/VibeGuardPanel.java")
  ]);

  assert.match(buildFile, /id\("org\.jetbrains\.intellij\.platform"\)/);
  assert.match(buildFile, /from\(lspBundle\)/);
  assert.match(buildFile, /dist\/tree-sitter/);
  assert.match(buildFile, /into\("lsp\/tree-sitter"\)/);
  assert.match(buildFile, /rename \{ "vibeguard-lsp\.js" \}/);
  assert.match(pluginXml, /com\.intellij\.modules\.lsp/);
  assert.match(pluginXml, /platform\.lsp\.serverSupportProvider/);
  assert.match(pluginXml, /<toolWindow id="VibeGuard"/);
  assert.match(pluginXml, /VibeGuardToolWindowFactory/);
  assert.match(provider, /ensureServerStarted\(new VibeGuardLspServerDescriptor\(project\)\)/);
  assert.match(descriptor, /new GeneralCommandLine\(nodeExecutable\(\), serverPath\(\), "--stdio"\)/);
  assert.match(descriptor, /new GeneralCommandLine\(nativePath, "--stdio"\)/);
  assert.match(descriptor, /VIBEGUARD_NODE_PATH/);
  assert.match(descriptor, /VIBEGUARD_LSP_PATH/);
  assert.match(descriptor, /VIBEGUARD_NATIVE_LSP_PATH/);
  assert.match(descriptor, /vibeguard\.native\.lsp\.path/);
  assert.match(descriptor, /lsp\/vibeguard-lsp\.js/);
  assert.match(bridge, /LspServerManager/);
  assert.match(bridge, /sendRequestSync/);
  assert.match(bridge, /workspace\/executeCommand|MANUAL_REVIEW_COMMAND/);
  assert.match(bridge, /vibeguard\.scanWithAi/);
  assert.match(bridge, /vibeguard\.cancelAiScan/);
  assert.match(panel, /Scan with AI/);
  assert.match(panel, /Cancelling AI deep scan/);
  assert.match(panel, /Allow VibeGuard Remote Review/);
  assert.match(panel, /Review & Apply Fix/);
});

function readJetBrainsFile(relativePath: string): Promise<string> {
  return fs.readFile(path.join(repositoryRoot, "jetbrains", relativePath), "utf8");
}

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const repositoryRoot = path.resolve(__dirname, "../..");

test("JetBrains plugin packages and starts the shared VibeGuard LSP server", async () => {
  const [buildFile, pluginXml, provider, descriptor] = await Promise.all([
    readJetBrainsFile("build.gradle.kts"),
    readJetBrainsFile("src/main/resources/META-INF/plugin.xml"),
    readJetBrainsFile("src/main/java/dev/vibeguard/jetbrains/VibeGuardLspServerSupportProvider.java"),
    readJetBrainsFile("src/main/java/dev/vibeguard/jetbrains/VibeGuardLspServerDescriptor.java")
  ]);

  assert.match(buildFile, /id\("org\.jetbrains\.intellij\.platform"\)/);
  assert.match(buildFile, /from\(lspBundle\)/);
  assert.match(buildFile, /dist\/tree-sitter/);
  assert.match(buildFile, /into\("lsp\/tree-sitter"\)/);
  assert.match(buildFile, /rename \{ "vibeguard-lsp\.js" \}/);
  assert.match(pluginXml, /com\.intellij\.modules\.lsp/);
  assert.match(pluginXml, /platform\.lsp\.serverSupportProvider/);
  assert.match(provider, /ensureServerStarted\(new VibeGuardLspServerDescriptor\(project\)\)/);
  assert.match(descriptor, /new GeneralCommandLine\(nodeExecutable\(\), serverPath\(\), "--stdio"\)/);
  assert.match(descriptor, /VIBEGUARD_NODE_PATH/);
  assert.match(descriptor, /VIBEGUARD_LSP_PATH/);
  assert.match(descriptor, /lsp\/vibeguard-lsp\.js/);
});

function readJetBrainsFile(relativePath: string): Promise<string> {
  return fs.readFile(path.join(repositoryRoot, "jetbrains", relativePath), "utf8");
}

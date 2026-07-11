# VibeGuard JetBrains Plugin

This IntelliJ Platform plugin is the JetBrains distribution described in the VibeGuard PRD. It starts the same bundled
`vibeguard-lsp --stdio` implementation used by the VS Code extension, CLI, and other LSP clients, so diagnostics and
safe quick fixes stay consistent across editors. It publishes L1 immediately while typing, debounces L2 and L3, and
runs all enabled layers immediately on save.

## Build

From the repository root, install Node dependencies once with `npm install`. Then build the plugin:

```powershell
cd jetbrains
.\gradlew.bat buildPlugin
```

The build runs `npm run build`, packages `dist/lspServer.js` inside the plugin, and writes the distributable ZIP to
`jetbrains/build/distributions/`.

The plugin targets JetBrains commercial IDEs with LSP support, starting at the 2025.2 platform release. It requires
Node.js 18 or later at runtime. By default it uses `node` from `PATH`; enterprise installations can override the
executable or server location with `VIBEGUARD_NODE_PATH` and `VIBEGUARD_LSP_PATH` respectively.

Open a supported JavaScript, TypeScript, Python, Rust, Go, Java, Kotlin, JSON, TOML, XML, or Gradle file to start the
project-wide language server. The JetBrains Language Services widget shows its status and surfaces the same VibeGuard
diagnostics and quick fixes as other clients.

## Marketplace Publishing

The Gradle `publishPlugin` task reads `JETBRAINS_MARKETPLACE_TOKEN` from the environment. A version tag is normally
published through the repository's `Marketplace Release` workflow; local publication is only for release maintainers:

```powershell
$env:JETBRAINS_MARKETPLACE_TOKEN = "marketplace-token"
.\gradlew.bat publishPlugin -PjetbrainsChannel=eap
```

# VibeGuard JetBrains Plugin

This IntelliJ Platform plugin is the JetBrains distribution described in the VibeGuard PRD. It starts the same bundled
`vibeguard-lsp --stdio` implementation used by the VS Code extension, CLI, and other LSP clients, so diagnostics and
safe quick fixes stay consistent across editors.

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

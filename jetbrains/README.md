# VibeGuard JetBrains Plugin

This IntelliJ Platform plugin is the JetBrains distribution described in the VibeGuard PRD. It starts the same bundled
`vibeguard-lsp --stdio` implementation used by the VS Code extension, CLI, and other LSP clients, so diagnostics and
safe quick fixes and local ignore actions stay consistent across editors. It publishes L1 immediately while typing,
debounces L2 and L3, and runs all enabled layers immediately on save. Unknown package imports use the local seed/index
first and are then verified against their registry asynchronously by default, so network latency does not block typing
feedback. Newly detected critical package findings also explain the Slopsquatting risk and open a standard LSP warning dialog,
where users can choose any verified safe package replacement or ignore the finding on its line, in its file, globally by rule, or by package name; each ignore choice
writes the shared `ignore-rules.yml` file. Clients with standard `showDocument` support can open that file directly from
the dialog through `Manage Ignore Rules`. The same choices remain available in the quick-fix menu. L3 generated
replacements always require an LSP confirmation and an evidence recheck before the server requests the edit.

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

For an explicit native preview, build [`../rust-lsp/`](../rust-lsp/) and set `VIBEGUARD_NATIVE_LSP_PATH` to the
resulting executable. The equivalent Java system property is `vibeguard.native.lsp.path`. This takes precedence over
the Node settings and starts the binary with `--stdio`, so Node is not needed for that preview. The native server
currently covers local L1 package-seed, provider and high-entropy secrets with conservative false-positive filtering,
unsafe-configuration, and high-confidence AI-error-pattern
diagnostics. It provides standard LSP quick fixes for safe npm seed replacements and mechanical configuration changes,
plus line, file, global-rule, and package ignore actions persisted to the shared `~/.vibeguard/ignore-rules.yml` file.
Set `VIBEGUARD_NATIVE_IGNORE_RULES_PATH` only to use an alternate shared-rule path in a managed or test environment.
In the background it also reads the shared JSON fallback index at `~/.vibeguard/package-index.json.gz` (or the
`VIBEGUARD_NATIVE_PACKAGE_INDEX_PATH` override) and only flags missing packages when a registry has `full` coverage.
It does not yet read the shared SQLite cache or perform package-cache synchronization, secret or AI-pattern fixes,
persisted findings, or L2/L3 analysis. Leave the
variable unset for the default full Node service.

When the server starts, it refreshes the shared `~/.vibeguard` package-name cache in the background according to
`config.json`. Workspace-root dependency manifests are prioritized, and updated indexes automatically recheck open
package findings without interrupting L1/L2/L3 editing feedback. JetBrains clients that support standard LSP work
progress receive native cache-sync stages and percentages in their language-service UI. Lightweight cache mode first
enables the quick partial index, then proceeds to the full index in Tier 2 unless `background_full_sync` is disabled.

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

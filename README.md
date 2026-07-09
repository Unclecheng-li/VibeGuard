# VibeGuard

VibeGuard is an IDE-first security scanner for AI-generated code. It focuses on the mistakes AI tools commonly introduce while you are coding: hallucinated package names, hardcoded secrets, unsafe framework configuration, and high-confidence insecure coding patterns.

This repository currently implements the Phase 1 MVP from `VibeGuard-PRD.md`:

- VSCode extension shell with real-time diagnostics and a findings sidebar
- L1 scanner for npm/PyPI hallucinated packages, hardcoded secrets, loose config, and AI error patterns
- Lightweight L2 SAST rules for common injection and unsafe deserialization cases
- Local package verification cache with offline seed mode and optional remote npm/PyPI checks
- CLI scanner for local and CI usage

## Development

```bash
npm install
npm run compile
npm test
```

To try the extension in VSCode, open this folder in VSCode and run the extension host from the debugger after compiling.

## CLI

```bash
npm run compile
node out/src/cli.js scan path/to/project --package-verification seed --fail-on high
node out/src/cli.js scan src --json
node out/src/cli.js scan . --ignore-rules ~/.vibeguard/ignore-rules.yml
```

## GitHub Action

```yaml
name: VibeGuard Security Scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vibeguard/vibeguard@v1
        with:
          path: .
          package_verification: seed
          fail_on: critical
          ignore_rules: .vibeguard/ignore-rules.yml
```

Package verification modes:

- `seed`: instant, offline checks against the built-in known-good/known-hallucinated catalog
- `remote`: seed + cached remote npm/PyPI verification with a 3 second timeout
- `off`: disables package existence checks

## Ignore Rules

VibeGuard reads `~/.vibeguard/ignore-rules.yml` by default. Ignored findings remain visible as dismissed items in editor views and JSON output, but they do not create diagnostics or fail the CLI threshold.

```yaml
ignore:
  - rule: "insecure_config_debug_true"
    scope: "file:**/test_*"
    reason: "test files may enable DEBUG"

  - path: "**/migrations/**"
    rules: ["sql_injection"]
    reason: "generated database migrations"

  - package: "@company/private-utils"
    registry: "npm"
    reason: "private internal package"
```

## LSP Server

```bash
npm run compile
node out/src/lspServer.js --stdio
```

The LSP server publishes VibeGuard diagnostics with the same scanner used by the VSCode extension and CLI.

## VSCode Settings

- `vibeguard.enabled`
- `vibeguard.scanOnChange`
- `vibeguard.scanOnSave`
- `vibeguard.packageVerification`: `seed`, `remote`, or `off`
- `vibeguard.enableL2`
- `vibeguard.showCriticalPopups`
- `vibeguard.ignoreRulesPath`

## Scope Notes

The PRD calls for a Rust LSP and SQLite package database. This MVP keeps the scanner API editor-agnostic and uses a JSON cache so the product can run immediately in the current environment. The cache and extension integration are intentionally isolated so a Rust LSP/SQLite backend can replace them without changing the rule model or user-facing findings.
"# VibeGuard" 

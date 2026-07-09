# VibeGuard

VibeGuard is an IDE-first security scanner for AI-generated code. It focuses on the mistakes AI tools commonly introduce while you are coding: hallucinated package names, hardcoded secrets, unsafe framework configuration, and high-confidence insecure coding patterns.

This repository currently implements the Phase 1 MVP from `VibeGuard-PRD.md`:

- VSCode extension shell with real-time diagnostics and a findings sidebar
- L1 scanner for npm/PyPI/Cargo/Go/Maven hallucinated packages, hardcoded secrets, loose config, and AI error patterns
- Lightweight L2 SAST rules for common injection and unsafe deserialization cases
- Optional local L3 semantic checks for API endpoints missing authentication, rate limiting, validation, or output encoding
- Local package verification cache with offline seed mode and optional remote npm/PyPI checks
- CLI scanner for local and CI usage

## Development

```bash
npm install
npm run build
npm test
```

To try the extension in VSCode, open this folder in VSCode and run the extension host from the debugger after building.

## CLI

```bash
npm run build
node dist/cli.js scan path/to/project --package-verification seed --fail-on high
node dist/cli.js scan src --json
node dist/cli.js scan src --l3
node dist/cli.js scan . --sarif vibeguard.sarif --github-annotations
node dist/cli.js scan . --ignore-rules ~/.vibeguard/ignore-rules.yml
node dist/cli.js scan src --package-index ~/.vibeguard/package-index.json
node dist/cli.js scan src --custom-rules ./vibeguard-rules.yml
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
```

`--l3` enables local semantic endpoint checks. It does not require an API key; the current MVP uses conservative heuristics to flag missing authentication, rate limiting, input validation, and output encoding around obvious route handlers.

## Package Index

The scanner can use a local package-name index before falling back to the seed catalog or remote registry checks. Partial indexes act as an existence cache; full indexes can also prove that a package is missing. Seed mode includes npm, PyPI, Cargo, Go modules, and Maven coordinates; remote registry lookups currently cover npm and PyPI.

```bash
node dist/cli.js packages import npm ./npm-packages.txt --partial --storage sqlite
node dist/cli.js packages import pypi ./pypi-packages.json --full --storage json
node dist/cli.js packages import cargo ./cargo-crates.txt --partial --storage sqlite
node dist/cli.js packages sync npm --limit 100000 --partial --storage sqlite
node dist/cli.js packages sync pypi --partial --storage json
node dist/cli.js packages status
node dist/cli.js packages check npm react
```

Supported import formats are newline-delimited package names, JSON arrays, `{ "packages": [...] }`, and npm `_all_docs` style `{ "rows": [{ "id": "package" }] }`.

Remote sync sources default to npm `_all_docs` and PyPI Simple API. Use `--limit` for a cold-start/lightweight partial index; VibeGuard will not store truncated remote results as `full` coverage.

Storage modes:

- `auto`: use SQLite when the current Node runtime supports `node:sqlite`, otherwise JSON
- `sqlite`: store package resolution cache and package index in `~/.vibeguard/packages.db`
- `json`: store verification results in `~/.vibeguard/package-cache.json` and package names in `~/.vibeguard/package-index.json`

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
          mode: full-scan
          ai_detection: author
          package_verification: seed
          fail_on: critical
          l3: false
          github_annotations: true
          sarif: vibeguard.sarif
          ignore_rules: .vibeguard/ignore-rules.yml
          custom_rules: .vibeguard/custom-rules.yml
          package_index: .vibeguard/package-index.json
          storage: auto
```

Package verification modes:

- `seed`: instant, offline checks against the built-in known-good/known-hallucinated catalog
- `remote`: seed + cached remote npm/PyPI verification with a 3 second timeout
- `off`: disables package existence checks

For pull request feedback, the Action can emit GitHub workflow annotations with `github_annotations: true`. Set `sarif` to write a SARIF 2.1.0 report that can be uploaded with `github/codeql-action/upload-sarif`.

Set `mode: ai-code-scan` to scan only changed files whose commits look AI-authored. `ai_detection` supports `author`, `message`, and `aggressive`; when git history cannot be inspected, VibeGuard falls back to a full scan so CI does not silently miss findings.

## Semgrep Export

VibeGuard can export its core AI/security rules to a Semgrep config file:

```bash
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
semgrep --config vibeguard-semgrep.yml .
```

The exported YAML keeps each VibeGuard rule id in `metadata.vibeguard.rule_id` so Semgrep results can be mapped back to VibeGuard findings.

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

## Custom Rules

Teams can add local YAML rules without rebuilding the extension:

```yaml
rules:
  - id: "company_public_s3_acl"
    pattern: "public-read"
    severity: "high"
    type: "insecure_config"
    layer: "L1"
    languages: ["json"]
    message: "S3 bucket ACL is public."
    suggestion: "Use private ACLs and bucket policies."
```

Use `--custom-rules ./vibeguard-rules.yml` in the CLI, `custom_rules` in the Action, or `vibeguard.customRules` in VSCode. Custom findings use rule ids like `custom.company_public_s3_acl`, so they can be ignored with the normal ignore-rules.yml flow.

## LSP Server

```bash
npm run build
node dist/lspServer.js --stdio
```

The LSP server publishes VibeGuard diagnostics with the same scanner used by the VSCode extension and CLI.

## VSCode Settings

- `vibeguard.enabled`
- `vibeguard.scanOnChange`
- `vibeguard.scanOnSave`
- `vibeguard.packageVerification`: `seed`, `remote`, or `off`
- `vibeguard.enableL2`
- `vibeguard.enableL3`
- `vibeguard.customRules`
- `vibeguard.showCriticalPopups`
- `vibeguard.ignoreRulesPath`

## VSCode Quick Fixes

VibeGuard publishes diagnostics with quick actions. When a finding has a safe mechanical fix, the editor lightbulb can apply it directly. Findings also expose ignore actions for the current finding, the current file, the global rule, or a hallucinated package name.

## Scope Notes

The PRD calls for a Rust LSP. This MVP keeps the scanner API editor-agnostic and uses a Node LSP plus SQLite/JSON storage backends so the product can run immediately in the current environment. The storage and extension integration are intentionally isolated so a Rust LSP backend can replace them without changing the rule model or user-facing findings.

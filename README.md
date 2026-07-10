# VibeGuard

VibeGuard is an IDE-first security scanner for AI-generated code. It focuses on the mistakes AI tools commonly introduce while you are coding: hallucinated package names, hardcoded secrets, unsafe framework configuration, and high-confidence insecure coding patterns.

This repository currently implements the Phase 1 MVP from `VibeGuard-PRD.md`:

- VSCode extension shell with real-time diagnostics and a findings sidebar
- L1 scanner for npm/PyPI/Cargo/Go/Maven hallucinated packages, hardcoded secrets, loose config, and expanded AI error patterns
- Lightweight L2 SAST rules for injection, unsafe deserialization, open redirect, and information leakage cases
- Optional L3 semantic checks with DeepSeek, Claude, OpenAI-compatible, or local Ollama providers, plus local heuristic fallback
- Local package verification cache with offline seed mode and optional remote npm/PyPI checks
- Local SQLite scan history in `~/.vibeguard/findings.db`
- CLI scanner for local and CI usage
- Shared `~/.vibeguard/config.json` defaults for CLI and VSCode scans

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
DEEPSEEK_API_KEY=... node dist/cli.js scan src --l3 --llm-provider deepseek
node dist/cli.js scan src --l3 --llm-provider local --llm-model llama3.2
node dist/cli.js scan . --sarif vibeguard.sarif --github-annotations
node dist/cli.js scan . --markdown vibeguard-report.md
node dist/cli.js scan . --format markdown
node dist/cli.js scan . --ignore-rules ~/.vibeguard/ignore-rules.yml
node dist/cli.js scan src --package-index ~/.vibeguard/package-index.json
node dist/cli.js scan src --custom-rules ./vibeguard-rules.yml
node dist/cli.js scan src --no-dedup-existing-tools
node dist/cli.js config init
node dist/cli.js scan . --config ~/.vibeguard/config.json
node dist/cli.js scan . --no-config
node dist/cli.js config ignore-finding vg_12345678
node dist/cli.js ignore-rules add-rule insecure_config_debug_true --path "**/test_*" --reason not_issue
node dist/cli.js ignore-rules add-package npm @company/private-utils
node dist/cli.js findings status
node dist/cli.js findings list --limit 20
node dist/cli.js findings summary --days 30
node dist/cli.js findings dashboard --days 30 --output vibeguard-dashboard.html
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
```

`--l3` enables semantic endpoint checks. When a configured provider has credentials, VibeGuard calls the LLM and expects structured JSON findings; without credentials, it falls back to conservative local heuristics for missing authentication, rate limiting, input validation, and output encoding around obvious route handlers. CLI/LSP API keys are read from environment variables such as `DEEPSEEK_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `VIBEGUARD_LLM_API_KEY`; the CLI intentionally has no plaintext API-key flag.

Provider controls:

```bash
node dist/cli.js scan src --l3 --llm-provider deepseek --llm-model deepseek-v4-flash
node dist/cli.js scan src --l3 --llm-provider claude --llm-api-key-env ANTHROPIC_API_KEY
node dist/cli.js scan src --l3 --llm-provider openai --llm-base-url https://api.openai.com/v1
node dist/cli.js scan src --l3 --llm-provider local --llm-base-url http://localhost:11434
```

The L1 secret scanner combines provider-specific signatures for keys and tokens, sensitive assignment context such as `apiKey`, `clientSecret`, `Authorization`, and `webhookSecret`, Shannon-entropy scoring for random-looking literals, and false-positive filters for placeholders, hashes, fixtures, UUIDs, and normal encoded data. High-confidence JavaScript/TypeScript and Python secret assignments include quick fixes that replace committed literals with environment-variable reads. The AI pattern library covers common generated-code mistakes such as placeholder credentials, unsafe JWT handling, wildcard CORS with credentials, disabled TLS verification, weak password hashing, plaintext password comparison, insecure random token generation, placeholder framework secrets, and public object-storage ACLs. L2 covers high-confidence SQL injection, XSS, SSRF, path traversal, unsafe deserialization, command injection, open redirect, and error-detail leakage patterns. High-confidence `innerHTML` and unsafe `yaml.load()` findings include mechanical quick fixes.

Use `--markdown path` to write a PR-friendly Markdown report alongside the normal console output, or `--format markdown` to make Markdown the primary output. CLI JSON, human, and Markdown reports include per-scan performance totals, layer timing totals, the slowest file, and warnings when L1/L2/L3 exceed the PRD performance budgets.

## Configuration

The CLI and VSCode extension read `~/.vibeguard/config.json` by default. Command-line flags and explicit VSCode user/workspace settings override the file; missing fields fall back to VibeGuard defaults.

```bash
node dist/cli.js config init
node dist/cli.js config path
```

```json
{
  "enabled": true,
  "detection_layers": {
    "l1": true,
    "l2": true,
    "l3": false
  },
  "package_verification": "seed",
  "llm_provider": "deepseek",
  "llm_api_key_stored": false,
  "llm_api_key": null,
  "dedup_with_existing_tools": true,
  "custom_rules": ["./rules/company-rules.yml"],
  "ignored_findings": ["vg_12345678"],
  "package_cache": {
    "languages": ["npm", "pypi"],
    "update_interval": "daily",
    "lightweight_mode": true
  },
  "telemetry": false
}
```

Relative `custom_rules` paths resolve from the config file directory. Use `--config path/to/config.json` for a project-specific file or `--no-config` to run with built-in defaults only.

`dedup_with_existing_tools` dismisses duplicate L2 findings when nearby SonarQube, Snyk, Semgrep, or CodeQL annotations already cover the same issue. Override it in the CLI with `--dedup-existing-tools` or `--no-dedup-existing-tools`.

Use `ignored_findings` for exact finding-id dismissals. The CLI can maintain this list without hand-editing JSON:

```bash
node dist/cli.js config ignore-finding vg_12345678
node dist/cli.js config unignore-finding vg_12345678
```

`llm_api_key` must remain `null`; VibeGuard rejects plaintext keys in config JSON. VSCode stores provider keys in SecretStorage via `VibeGuard: Set LLM API Key` and only updates the boolean `llm_api_key_stored` marker. CLI and LSP users should provide keys through environment variables.

## Findings Storage

CLI and VSCode scans persist scan runs and findings to `~/.vibeguard/findings.db` by default. Stored dismissed findings remain queryable for audit trails, while normal diagnostics and fail thresholds still use only active findings.

```bash
node dist/cli.js findings status
node dist/cli.js findings list --limit 20
node dist/cli.js findings list --all --json
node dist/cli.js findings summary --days 30 --top 10
node dist/cli.js findings summary --json
node dist/cli.js findings dashboard --days 30 --top 10 --output vibeguard-dashboard.html
node dist/cli.js findings prune --days 30
node dist/cli.js scan . --findings-db ~/.vibeguard/findings.db
node dist/cli.js scan . --no-store-findings
```

`findings summary` aggregates stored history by severity, type, top detection rules, dismissal reason, git author, and daily trend, providing a stable JSON shape for CI summaries or a future team dashboard. CLI and VSCode scans record the latest git author for files with findings when git history is available, so the summary and dashboard can surface developer risk hotspots. `findings dashboard` writes a standalone HTML dashboard with the same trend, author, and dismissal-reason data, suitable for CI artifacts, team reports, false-positive review, or offline review. VSCode users can run `VibeGuard: Export Findings Dashboard` to generate and open the same dashboard from the command palette.

GitHub Action scans default to `store_findings: false` so CI jobs do not write local history unless explicitly requested.

## Package Index

The scanner can use a local package-name index before falling back to the seed catalog or remote registry checks. Partial indexes act as an existence cache; full indexes can also prove that a package is missing and suggest close package names for typos or slopsquatting-like hallucinations. Seed mode includes npm, PyPI, Cargo, Go modules, and Maven coordinates; remote registry lookups currently cover npm and PyPI. Local package-name sync can populate indexes for npm, PyPI, Cargo, Go modules, and Maven.

```bash
node dist/cli.js packages import npm ./npm-packages.txt --partial --storage sqlite
node dist/cli.js packages import pypi ./pypi-packages.json --full --storage json
node dist/cli.js packages import cargo ./cargo-crates.txt --partial --storage sqlite
node dist/cli.js packages sync npm --limit 100000 --partial --storage sqlite
node dist/cli.js packages sync pypi --partial --storage json
node dist/cli.js packages sync cargo --limit 100 --partial --storage sqlite
node dist/cli.js packages sync gomod --partial --storage sqlite
node dist/cli.js packages sync maven --limit 1000 --partial --storage json
node dist/cli.js packages sync-config --config ~/.vibeguard/config.json --storage sqlite
node dist/cli.js packages status
node dist/cli.js packages check npm react
```

Supported import formats are newline-delimited package names, JSON arrays, `{ "packages": [...] }`, and npm `_all_docs` style `{ "rows": [{ "id": "package" }] }`.

Remote sync sources default to npm `_all_docs`, PyPI Simple API, crates.io, Go module index, and Maven Central search. Cargo and Maven sync paginate through crates.io and Maven Central search results when needed. Use `--limit` for a cold-start/lightweight partial index where the upstream supports bounded results; VibeGuard will not store truncated remote results as `full` coverage.

When a package is absent from a full local index, VibeGuard combines curated seed suggestions with fuzzy matches from the synced index. The first close match is exposed as an editor/CLI fix when the import specifier can be safely replaced.

`packages sync-config` reads `package_cache.languages`, `package_cache.update_interval`, and `package_cache.lightweight_mode` from config.json. It skips fresh registries, refreshes stale registries, and upgrades partial indexes when lightweight mode is disabled. Use `--force` to refresh everything now, `--limit` to override the lightweight target, and `--url registry=URL` for a registry mirror or test fixture.

The VSCode extension also starts a background package-cache sync on startup. It prioritizes package managers detected in the current workspace, shows `VibeGuard: package sync` in the status bar while running, logs details to the VibeGuard output channel, and keeps other L1/L2/L3 checks active if the cache refresh fails. Run `VibeGuard: Sync Package Cache` from the command palette to force a refresh.

In VSCode, normal edit-time scans run L1 immediately for fast feedback, then debounce L2 SAST for 500ms by default. When L3 is enabled, semantic analysis is debounced for 2 seconds after edits by default; saves and manual scans run all enabled layers immediately. Adjust these with `vibeguard.l2DebounceMs` and `vibeguard.l3DebounceMs`. The status bar tooltip includes recent scan timing totals and shows a watch marker when a file exceeds the L1/L2/L3 performance budget.

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
    env:
      DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
    steps:
      - uses: actions/checkout@v4
      - id: vibeguard
        uses: vibeguard/vibeguard@v1
        with:
          path: .
          mode: full-scan
          ai_detection: author
          package_verification: seed
          fail_on: critical
          l3: true
          llm_provider: deepseek
          llm_model: deepseek-v4-flash
          llm_api_key_env: DEEPSEEK_API_KEY
          github_annotations: true
          sarif: vibeguard.sarif
          markdown: vibeguard-report.md
          step_summary: true
          pr_comment: false
          config: .vibeguard/config.json
          dedup_existing_tools: true
          store_findings: true
          dashboard: true
          dashboard_path: vibeguard-dashboard.html
          ignore_rules: .vibeguard/ignore-rules.yml
          custom_rules: .vibeguard/custom-rules.yml
          package_index: .vibeguard/package-index.json
          storage: auto
      - uses: actions/upload-artifact@v4
        if: always() && steps.vibeguard.outputs.dashboard_path != ''
        with:
          name: vibeguard-dashboard
          path: ${{ steps.vibeguard.outputs.dashboard_path }}
```

Package verification modes:

- `seed`: instant, offline checks against the built-in known-good/known-hallucinated catalog
- `remote`: seed + cached remote npm/PyPI verification with a 3 second timeout
- `off`: disables package existence checks

For pull request feedback, the Action can emit GitHub workflow annotations with `github_annotations: true`, append a Markdown report to the job summary with `step_summary: true`, and optionally create/update a sticky PR comment with `pr_comment: true`. Set `sarif` to write a SARIF 2.1.0 report that can be uploaded with `github/codeql-action/upload-sarif`; set `markdown` to keep the Markdown report as an artifact path. Set `store_findings: true` and `dashboard: true` to generate a standalone HTML findings dashboard, then upload `steps.vibeguard.outputs.dashboard_path` as a CI artifact.

Set `mode: ai-code-scan` to scan only changed files whose commits look AI-authored. `ai_detection` supports `author`, `message`, and `aggressive`; when git history cannot be inspected, VibeGuard falls back to a full scan so CI does not silently miss findings.

## Semgrep Export

VibeGuard can export its core AI/security rules to a Semgrep config file. Built-in AI pattern rules are exported from the same rule definitions used by the scanner. Provider-specific secret signatures are exported directly; contextual high-entropy secret detection is exported as a conservative regex approximation because the full Shannon-entropy and false-positive filtering logic runs inside the VibeGuard scanner.

```bash
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
semgrep --config vibeguard-semgrep.yml .
```

The exported YAML keeps each VibeGuard rule id in `metadata.vibeguard.rule_id` so Semgrep results can be mapped back to VibeGuard findings.

## Ignore Rules

VibeGuard reads `~/.vibeguard/ignore-rules.yml` by default. Ignored findings remain visible as dismissed items in editor views and JSON output, but they do not create diagnostics or fail the CLI threshold.

VSCode ignore actions ask for a reason before writing a rule. Standard reasons include `False positive`, `Not an issue`, and `Internal package`, with a custom reason option for team-specific context. The selected reason is stored in `ignore-rules.yml` and shown as the dismissed reason in reports.

CLI users can append the same YAML rules without hand-editing the file:

```bash
node dist/cli.js ignore-rules add-rule insecure_config_debug_true --path "**/test_*" --reason not_issue
node dist/cli.js ignore-rules add-rule sql_injection --path "migrations/**" --reason "generated migration"
node dist/cli.js ignore-rules add-package npm @company/private-utils
```

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

Use `--custom-rules ./vibeguard-rules.yml` in the CLI, `custom_rules` in `config.json`, `custom_rules` in the Action, or `vibeguard.customRules` in VSCode. Custom findings use rule ids like `custom.company_public_s3_acl`, so they can be ignored with the normal ignore-rules.yml flow.

## LSP Server

```bash
npm run build
node dist/lspServer.js --stdio
```

The LSP server publishes VibeGuard diagnostics with the same scanner used by the VSCode extension and CLI. It also exposes LSP `quickfix` code actions for findings that have safe mechanical fixes, so non-VSCode LSP clients can apply the same package-name, secret-assignment, config, and SAST edits.

## VSCode Settings

- `vibeguard.enabled`
- `vibeguard.scanOnChange`
- `vibeguard.scanOnSave`
- `vibeguard.configPath`
- `vibeguard.packageVerification`: `seed`, `remote`, or `off`
- `vibeguard.autoSyncPackageCache`
- `vibeguard.packageCacheLanguages`
- `vibeguard.packageCacheUpdateInterval`
- `vibeguard.packageCacheLightweightMode`
- `vibeguard.enableL2`
- `vibeguard.l2DebounceMs`
- `vibeguard.enableL3`
- `vibeguard.l3DebounceMs`
- `vibeguard.llmProvider`
- `vibeguard.llmModel`
- `vibeguard.llmBaseUrl`
- `vibeguard.dedupWithExistingTools`
- `vibeguard.storeFindings`
- `vibeguard.findingsDbPath`
- `vibeguard.ignoredFindings`
- `vibeguard.customRules`
- `vibeguard.showCriticalPopups`
- `vibeguard.ignoreRulesPath`

LLM commands:

- `VibeGuard: Set LLM API Key`
- `VibeGuard: Delete LLM API Key`
- `VibeGuard: Show LLM Status`

Dashboard command:

- `VibeGuard: Export Findings Dashboard`

## VSCode Quick Fixes

VibeGuard publishes diagnostics with quick actions. When a finding has a safe mechanical fix, the editor lightbulb or an LSP client quickfix can apply it directly. Current fixes cover known package-name replacements, hardcoded secret assignments to environment-variable reads, debug/CORS/host-check toggles, `yaml.load()` to `yaml.safe_load()`, and high-confidence `innerHTML` to `textContent` cases. The VSCode extension also exposes ignore actions for the current finding, the current file, the global rule, or a hallucinated package name.

## Scope Notes

The PRD calls for a Rust LSP. This MVP keeps the scanner API editor-agnostic and uses a Node LSP plus SQLite/JSON storage backends so the product can run immediately in the current environment. The storage and extension integration are intentionally isolated so a Rust LSP backend can replace them without changing the rule model or user-facing findings.

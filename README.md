<div align="center">

<img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/VibeGuardIcon.png" width="120" height="120" alt="VibeGuard">

<h1>VibeGuard</h1>

<p><strong>IDE-first security scanner for AI-generated code</strong></p>

<p>Catch what AI missed — hallucinated packages, hardcoded secrets, unsafe configs, and common AI coding mistakes — right in your editor, in real time.</p>

<p>
  <a href="https://github.com/Unclecheng-li/VibeGuard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Unclecheng-li/VibeGuard/ci.yml?branch=main&logo=github&label=CI" alt="CI"></a>
  <a href="https://github.com/Unclecheng-li/VibeGuard/releases"><img src="https://img.shields.io/github/v/release/Unclecheng-li/VibeGuard?display_name=tag&logo=github" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Unclecheng-li/VibeGuard?color=blue" alt="License"></a>
  <a href="https://github.com/Unclecheng-li/VibeGuard/stargazers"><img src="https://img.shields.io/github/stars/Unclecheng-li/VibeGuard?style=social" alt="Stars"></a>
</p>

<p>
  <img src="https://img.shields.io/badge/VSCode-1.92+-007ACC?logo=visualstudiocode&logoColor=white" alt="VSCode">
  <img src="https://img.shields.io/badge/JetBrains-2025.2+-000000?logo=jetbrains&logoColor=white" alt="JetBrains">
  <img src="https://img.shields.io/badge/Node.js-22%20LTS-339933?logo=node.js&logoColor=white" alt="Node.js 22 LTS">
  <img src="https://img.shields.io/badge/Rust-LSP%20Preview-CE422B?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" alt="Docker">
</p>

</div>

---

## Screenshots

<div align="center">
<table>
<tr>
<td align="center"><b>Real-time diagnostics</b></td>
<td align="center"><b>Hover for details</b></td>
</tr>
<tr>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/realtime-diagnostic.png" alt="Real-time diagnostics" width="400"></td>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/hover-tooltip.png" alt="Hover tooltip" width="400"></td>
</tr>
<tr>
<td align="center"><b>Quick Fix menu</b></td>
<td align="center"><b>Problems panel</b></td>
</tr>
<tr>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/quick-fix.png" alt="Quick Fix menu" width="400"></td>
<td><img src="https://raw.githubusercontent.com/Unclecheng-li/VibeGuard/main/media/demonstration/problems-panel.png" alt="Problems panel" width="400"></td>
</tr>
</table>
</div>

---

## Why VibeGuard?

AI coding assistants are fast — but they hallucinate packages, leak secrets, and skip security controls. VibeGuard catches those mistakes **as you type**, before they reach production.

- **Hallucinated packages** — non-existent npm/PyPI/Cargo/Go/Maven packages
- **Hardcoded secrets** — API keys, tokens, credentials left in source
- **Unsafe configurations** — debug mode, wildcard CORS, disabled TLS
- **Insecure coding patterns** — injection, XSS, SSRF, path traversal, and more

## Quick Start

```bash
git clone https://github.com/vibeguard/vibeguard.git
cd vibeguard
nvm use          # Node.js 22 LTS
npm install
npm run build
```

**VSCode** — Open the folder in VSCode, press `F5` to launch the Extension Development Host.

**CLI** — Scan any project:

```bash
node dist/cli.js scan path/to/project --fail-on high
node dist/cli.js scan src --json
node dist/cli.js scan . --sarif vibeguard.sarif
```

**Docker** — No local install needed:

```bash
docker build -t vibeguard:local .
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --fail-on high
```

Watch the [14-second CLI demo](media/vibeguard-demo.mp4) for a real scan of the deliberately unsafe [demo sample](demo/unsafe-ai-sample.ts).

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Editor / IDE                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  VSCode  │  │ JetBrains│  │  Any LSP Client  │  │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
│       │              │                 │             │
│       └──────────────┴─────────────────┘             │
│                      │ LSP Protocol                  │
│              ┌───────┴────────┐                      │
│              │  VibeGuard LSP │                      │
│              │  (Node / Rust) │                      │
│              └───────┬────────┘                      │
│    ┌─────────────────┼─────────────────┐            │
│    │                 │                 │            │
│  ┌─┴──┐  ┌──────┐  ┌──────┐  ┌──────────────┐     │
│  │ L1 │  │  L2  │  │  L3  │  │  Package     │     │
│  │<50ms│  │<2s   │  │<5s   │  │  Cache/Sync  │     │
│  └────┘  └──────┘  └──────┘  └──────────────┘     │
└─────────────────────────────────────────────────────┘
         │                    │
   ┌─────┴─────┐      ┌──────┴──────┐
   │  SQLite   │      │  Registries │
   │ findings  │      │ npm/PyPI/   │
   │   .db     │      │ Cargo/Go/   │
   └───────────┘      │ Maven       │
                      └─────────────┘
```

| Layer | What | Speed | How |
|-------|------|-------|-----|
| **L1** | Hallucinated packages, secrets, config, AI patterns | < 50ms | Regex + entropy + seed catalog |
| **L2** | SQL injection, XSS, SSRF, path traversal, etc. | < 2s | Tree-sitter WASM AST analysis |
| **L3** | Missing auth/rate-limit/validation, semantic gaps | < 5s | LLM (DeepSeek/Claude/OpenAI/Ollama/Pro) + local heuristics |

## Key Features

- **VSCode Extension** — real-time diagnostics with a findings sidebar
- **JetBrains Plugin** — bundled LSP server for JetBrains 2025.2+ IDEs
- **L1 Hallucination Detector** — package checks across 5 registries, Java class imports, hardcoded secrets, loose config, 31 AI error patterns
- **L2 Tree-sitter SAST** — JS/TS/Python/Java injection, XSS, SSRF, deserialization, redirects, info leakage
- **L3 Semantic Analysis** — DeepSeek, Claude, OpenAI-compatible, local Ollama, or VibeGuard Pro; local heuristic fallback when no API key
- **CLI Scanner** — local and CI usage with JSON/SARIF/Markdown output
- **Package Cache** — offline seed mode + optional remote checks for npm/PyPI/Cargo/Go/Maven
- **SQLite History** — local scan history in `~/.vibeguard/findings.db`
- **Team Dashboard** — deployable dashboard with developer risk, compliance, and trend views
- **GitHub Action** — PR annotations, SARIF, Markdown reports, AI-code-scan mode

## Table of Contents

- [CLI](#cli)
- [Configuration](#configuration)
- [VSCode Integration](#vscode-integration)
- [JetBrains Plugin](#jetbrains-plugin)
- [LSP Server](#lsp-server)
- [Docker](#docker)
- [Team Dashboard](#team-dashboard)
- [Pro Subscription](#pro-subscription)
- [GitHub Action](#github-action)
- [Package Index](#package-index)
- [Ignore Rules](#ignore-rules)
- [Custom Rules](#custom-rules)
- [Semgrep Export](#semgrep-export)
- [Findings Storage](#findings-storage)
- [Scope Notes](#scope-notes)
- [Contributing](#contributing)
- [License](#license)

## CLI

### Basic Usage

```bash
node dist/cli.js scan path/to/project --package-verification seed --fail-on high
node dist/cli.js scan src --json
node dist/cli.js scan . --sarif vibeguard.sarif --github-annotations
node dist/cli.js scan . --markdown vibeguard-report.md
node dist/cli.js scan . --format markdown
node dist/cli.js scan . --ignore-rules ~/.vibeguard/ignore-rules.yml
node dist/cli.js scan src --custom-rules ./vibeguard-rules.yml
node dist/cli.js scan src --no-dedup-existing-tools
node dist/cli.js config init
node dist/cli.js config ignore-finding vg_12345678
```

### L3 Semantic Analysis

```bash
DEEPSEEK_API_KEY=... node dist/cli.js scan src --l3 --llm-provider deepseek
VIBEGUARD_PRO_API_KEY=... node dist/cli.js scan src --l3 --llm-provider vibeguard
node dist/cli.js scan src --l3 --llm-provider local --llm-model llama3.2
```

`--l3` enables semantic endpoint checks. When a configured provider has credentials, VibeGuard calls the LLM with detected framework, function, and route context. Before source is sent to a remote provider, high-confidence secret literals are replaced with placeholders, and only the source filename is included rather than its directory path. Local Ollama analysis keeps source local entirely.

Without credentials, VibeGuard falls back to conservative local heuristics for missing authentication, rate limiting, input validation, parameterized database queries, IO error handling, and output encoding around Express, FastAPI/Flask, Django, and Spring MVC route handlers.

**Framework coverage:**

- **Django** — resolves same-file `urlpatterns` `path`/`re_path` entries and standalone `views.py` function views
- **Spring MVC** — includes class-level `@RequestMapping` prefixes; recognizes `@PreAuthorize`, `@RateLimiter`, `@Valid`, and `try`/`catch`
- **Express** — recognizes same-file `app.use`/`router.use` authentication and rate-limit middleware

**Provider controls:**

```bash
node dist/cli.js scan src --l3 --llm-provider deepseek --llm-model deepseek-v4-flash
node dist/cli.js scan src --l3 --llm-provider claude --llm-api-key-env ANTHROPIC_API_KEY
node dist/cli.js scan src --l3 --llm-provider openai --llm-base-url https://api.openai.com/v1
node dist/cli.js scan src --l3 --llm-provider local --llm-base-url http://localhost:11434
node dist/cli.js llm-key set --provider deepseek --from-env DEEPSEEK_API_KEY
node dist/cli.js llm-key status --provider deepseek
```

Remote LLM base URLs must use HTTPS. HTTP is accepted only for `localhost`/`127.0.0.1` loopback development.

### Detection Coverage

**L1 — Secret scanner** — provider-specific signatures, sensitive assignment context, Shannon-entropy scoring, false-positive filters for placeholders/hashes/fixtures/UUIDs. High-confidence JS/TS and Python secret assignments include quick fixes that replace committed literals with environment-variable reads.

**L1 — AI pattern library** — placeholder credentials, unsafe JWT handling, wildcard CORS with credentials, disabled TLS verification, weak password hashing, plaintext password comparison, insecure random token generation, placeholder framework secrets, public object-storage ACLs.

**L2 — SAST:**

| Pattern | Coverage |
|---------|----------|
| SSRF | Fetch, Axios, Node HTTP(S), Requests, HTTPX, Java `RestTemplate`, `WebClient`, JDK `HttpRequest`, OkHttp |
| Command injection | Node `exec`/`execSync`, shell-enabled `spawn`/`execFile`, Python execution APIs |
| Path traversal | Node `fs`/`fs.promises`, Java `Files`/`Paths`/`File` |
| Open redirect (Java) | Servlet, `RedirectView`, `redirect:` targets |
| Error leakage (Java) | 5xx Servlet or Spring responses returning exception messages |

High-confidence `innerHTML` and unsafe `yaml.load()` findings include mechanical quick fixes.

### Findings Management

```bash
node dist/cli.js findings status
node dist/cli.js findings list --limit 20
node dist/cli.js findings list --all --json
node dist/cli.js findings summary --days 30 --top 10
node dist/cli.js findings dashboard --days 30 --top 10 --output vibeguard-dashboard.html
node dist/cli.js findings compliance --framework all --days 90 --output vibeguard-compliance-report.md
node dist/cli.js findings audit --limit 100
node dist/cli.js findings prune --days 30
node dist/cli.js scan . --no-store-findings
```

`findings summary` aggregates by severity, type, top rules, dismissal reason, git author, daily trend, and active-finding delta. `findings dashboard` writes a standalone HTML dashboard for CI artifacts. `findings compliance` writes a Markdown evidence report for SOC2/ISO27001.

## Configuration

The CLI and VSCode extension read `~/.vibeguard/config.json` by default. CLI flags and VSCode settings override the file.

```bash
node dist/cli.js config init
node dist/cli.js config path
```

```json
{
  "enabled": true,
  "detection_layers": { "l1": true, "l2": true, "l3": false },
  "package_verification": "seed",
  "llm_provider": "deepseek",
  "dedup_with_existing_tools": true,
  "custom_rules": ["./rules/company-rules.yml"],
  "package_cache": {
    "languages": ["npm", "pypi"],
    "update_interval": "daily",
    "lightweight_mode": true,
    "background_full_sync": true
  },
  "telemetry": false
}
```

### LLM API Key Storage

`llm_api_key` must remain `null` in config JSON — VibeGuard rejects plaintext keys.

| Environment | Storage |
|-------------|---------|
| VSCode | SecretStorage via `VibeGuard: Set LLM API Key` |
| CLI / LSP | `vibeguard llm-key set --provider <p> --from-env <VAR>` — Windows DPAPI, macOS Keychain, Linux Secret Service |
| Fallback | `VIBEGUARD_LLM_CREDENTIAL_PIN` (8+ chars) → scrypt + AES-256-GCM |

### Deduplication

`dedup_with_existing_tools` dismisses duplicate L2 findings when nearby SonarQube, Snyk, Semgrep, or CodeQL annotations already cover the same issue.

### Telemetry

Set `telemetry: true` to contribute anonymous false-positive feedback. Events include only a truncated SHA-256 rule fingerprint, finding type/layer/severity, and ignore scope — never source code, file paths, or project identifiers.

## VSCode Integration

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `vibeguard.enabled` | `true` | Enable/disable scanning |
| `vibeguard.scanOnChange` | `true` | Scan on document change |
| `vibeguard.scanOnSave` | `true` | Scan on document save |
| `vibeguard.configPath` | — | Path to config file |
| `vibeguard.packageVerification` | `remote` | `remote`, `seed`, or `off` |
| `vibeguard.enableL2` | `true` | Enable L2 SAST |
| `vibeguard.l2DebounceMs` | `500` | L2 debounce |
| `vibeguard.enableL3` | `false` | Enable L3 semantic analysis |
| `vibeguard.l3DebounceMs` | `2000` | L3 debounce |
| `vibeguard.llmProvider` | — | LLM provider for L3 |
| `vibeguard.llmModel` | — | LLM model name |
| `vibeguard.dedupWithExistingTools` | `true` | Dedup with SonarQube/Snyk/Semgrep/CodeQL |
| `vibeguard.storeFindings` | `true` | Persist to SQLite |
| `vibeguard.customRules` | — | Custom rules YAML paths |
| `vibeguard.showCriticalPopups` | `true` | Show critical finding dialogs |

### Commands

- `VibeGuard: Set LLM API Key` — store provider key in SecretStorage
- `VibeGuard: Delete LLM API Key` — remove stored key
- `VibeGuard: Show LLM Status` — display provider and key status
- `VibeGuard: Show Pro Subscription Status` — display Pro plan and usage
- `VibeGuard: Review and Apply All Pro Fixes in Current File` — multi-select L3 replacements
- `VibeGuard: Export Findings Dashboard` — generate HTML dashboard
- `VibeGuard: Sync Package Cache` — force cache refresh
- `VibeGuard: Apply All Safe Fixes in Current File` — batch L1/L2 mechanical fixes

### Quick Fixes

VibeGuard publishes diagnostics with quick actions. Available fixes include:

- **Hallucinated packages** — verified similar-name candidates (best match marked preferred)
- **Hardcoded secrets** → environment-variable reads
- **Debug/CORS/host-check toggles** — mechanical config fixes
- **`yaml.load()`** → `yaml.safe_load()`
- **SQL f-strings** → parameterized `execute()` calls
- **`innerHTML`** → `textContent`

Before applying a fix, VSCode verifies the original finding evidence still matches the open document. `VibeGuard: Apply All Safe Fixes in Current File` applies non-overlapping L1/L2 fixes in one reviewed operation.

### Edit-Time Scanning

L1 runs immediately for fast feedback. L2 SAST debounces for 500ms by default. Package verification defaults to `remote`: local seed/cache results first, then async remote registry checks after 600ms delay. L3 (when enabled) debounces for 2 seconds.

The status bar shows scan timing and a watch marker when a file exceeds the L1/L2/L3 performance budget.

## JetBrains Plugin

The JetBrains module reuses `vibeguard-lsp --stdio` for diagnostics matching the CLI and VSCode extension. Targets JetBrains 2025.2+ with LSP API.

```bash
cd jetbrains
./gradlew buildPlugin
```

The distribution ZIP is in `jetbrains/build/distributions/`. Use `VIBEGUARD_NODE_PATH` or `VIBEGUARD_LSP_PATH` to override the Node executable in managed environments.

To try the native Rust L1 preview, build `rust-lsp` and set `VIBEGUARD_NATIVE_LSP_PATH`. See [jetbrains/README.md](jetbrains/README.md) for coverage and Windows instructions.

## LSP Server

```bash
npm run build
node dist/lspServer.js --stdio
```

**Debounce:**

| Event | L1 | L2 | L3 |
|-------|----|----|----|
| Edit | Immediate | 500ms | 2s |
| Save | Immediate | Immediate | Immediate |

Critical findings use the standard LSP warning dialog with safe fixes plus ignore actions. The server exposes LSP `quickfix` code actions for non-VSCode clients.

## Docker

```bash
docker build -t vibeguard:local .
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --fail-on high
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --mode ai-code-scan --ai-detection aggressive
```

The image packages the CLI, LSP bundle, and Tree-sitter WASM grammars with Git included for `ai-code-scan` history inspection.

## Team Dashboard

`findings serve` turns scan history into a deployable team dashboard (default `127.0.0.1:8787`) with developer risk, rule, severity, trend, compliance, and feedback-signal views.

> **Warning:** Use `--host 0.0.0.0` only behind a private network or reverse proxy.

### Authentication

| Method | Use case |
|--------|----------|
| **Service Token** | Small private deployment — `VIBEGUARD_DASHBOARD_TOKEN` env var |
| **OIDC** | Enterprise — authorization code flow with PKCE, JWKS validation, role mapping |
| **Project-scoped ingest token** | CI upload without dashboard admin token |

OIDC role mapping:

| Role | Access |
|------|--------|
| `viewer` (default) | `/`, `/api/summary` |
| `analyst` | + `/api/findings`, `/api/compliance` |
| `admin` | + `/api/findings?all=true`, `/api/audit` |

### Deployment

**Docker:**

```bash
docker run --rm -p 8787:8787 -e VIBEGUARD_DASHBOARD_TOKEN \
  -v "$PWD/.vibeguard:/data" vibeguard:local \
  findings serve --db /data/findings.db --host 0.0.0.0 --token-env VIBEGUARD_DASHBOARD_TOKEN
```

**Docker Compose** — `deploy/compose.yaml` packages a persistent SQLite volume, health check, and security hardening. See `deploy/.env.example` for required variables.

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
```

For enterprise OIDC, merge the override:

```bash
docker compose --env-file deploy/.env \
  -f deploy/compose.yaml -f deploy/compose.oidc.yaml up -d --build
```

### Central CI Ingestion

Private dashboards can receive scan history from CI via `POST /api/ingest` with a dedicated ingest token. Project-scoped credentials can be issued through `/api/projects` — the raw token is returned only once, SQLite stores only its SHA-256 digest.

```bash
VIBEGUARD_FINDINGS_INGEST_TOKEN=replace-with-ci-token \
  node dist/cli.js scan . --no-store-findings \
  --findings-endpoint https://guard.example.com/api/ingest \
  --findings-token-env VIBEGUARD_FINDINGS_INGEST_TOKEN \
  --findings-project acme/payments-api
```

Dashboard administrators can manage project credentials and custom-rule YAML from the `Project integrations` page. See [Team Dashboard docs](#) for the full API reference.

## Pro Subscription

The `vibeguard` L3 provider uses the hosted service with server-enforced Pro/Team/Enterprise allowance. Free BYOK paths (DeepSeek, Claude, OpenAI-compatible, local Ollama) remain available without subscription.

| Environment | Method |
|-------------|--------|
| CI / Docker | `VIBEGUARD_PRO_API_KEY` env var |
| CLI / LSP | `vibeguard llm-key set --provider vibeguard --from-env VIBEGUARD_PRO_API_KEY` |
| VSCode | `VibeGuard: Set LLM API Key` with provider `vibeguard` |

```bash
export VIBEGUARD_PRO_API_KEY=replace-with-pro-credential
node dist/cli.js llm-key set --provider vibeguard --from-env VIBEGUARD_PRO_API_KEY
node dist/cli.js scan src --l3 --llm-provider vibeguard
node dist/cli.js subscription status
```

Default service origin: `https://api.vibeguard.dev/v1`. Private deployments can set `VIBEGUARD_PRO_API_BASE_URL` (HTTPS only). The hosted contract is OpenAI-compatible; billing and limits remain server-side.

## GitHub Action

```yaml
name: VibeGuard Security Scan
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
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
          llm_api_key_env: DEEPSEEK_API_KEY
          github_annotations: true
          sarif: vibeguard.sarif
          markdown: vibeguard-report.md
          step_summary: true
          pr_review_comments: true
          pr_review_comment_limit: 20
          dedup_existing_tools: true
          dashboard: true
          dashboard_path: vibeguard-dashboard.html
          compliance: true
          compliance_path: vibeguard-compliance-report.md
          compliance_framework: all
          compliance_days: 90
      - uses: actions/upload-artifact@v4
        if: always() && steps.vibeguard.outputs.dashboard_path != ''
        with:
          name: vibeguard-dashboard
          path: ${{ steps.vibeguard.outputs.dashboard_path }}
```

### Package Verification Modes

| Mode | Description |
|------|-------------|
| `seed` | Instant, offline checks against built-in catalog |
| `remote` | Seed + cached remote registry verification (3s timeout, max 5 in-flight) |
| `off` | Disables package existence checks |

### AI Code Scan Mode

Set `mode: ai-code-scan` to report only findings on changed lines attributed to AI. Uses `git blame` with configurable detection:

| `ai_detection` | Matches |
|-----------------|---------|
| `author` | The blamed author |
| `message` | The blamed commit body or trailers |
| `aggressive` | Either signal + additions of 50+ lines |

Falls back to full scan when git history is unavailable.

### PR Feedback Options

- `github_annotations: true` — workflow annotations
- `step_summary: true` — append Markdown to job summary
- `pr_comment: true` — sticky PR comment
- `pr_review_comments: true` — inline review comments on changed diff lines (limit: `pr_review_comment_limit`)
- `sarif` / `markdown` — report artifacts

### Central Rules

Set `findings_rules_endpoint` to download centrally managed YAML rules from the private dashboard. Uses the same project credential, accepts HTTPS only, never writes the token to output. `findings_rules_required: true` fails the job on download errors.

## Package Index

The scanner uses a local package-name index before falling back to the seed catalog or remote checks.

**Default modes:**

| Environment | Default | Behavior |
|-------------|---------|----------|
| VSCode / LSP | `remote` | Local seed/index first, then async remote verification |
| CLI / Action | `seed` | Deterministic offline scans |

### Supported Registries

| Registry | Source | Notes |
|----------|--------|-------|
| npm | `_all_docs` | Conditional refresh with `_changes` incremental sync |
| PyPI | Simple API | Imports, manifests, `pip install`, notebooks, Dockerfiles |
| Cargo | crates.io | Resolves aliases; skips `path`/`git`/custom `registry` |
| Go | module index | — |
| Maven | Maven Central | Verifies exact Java/Kotlin import classes |

### CLI Commands

```bash
# Import a local package list
node dist/cli.js packages import npm ./npm-packages.txt --partial --storage sqlite
node dist/cli.js packages import pypi ./pypi-packages.json --full --storage json

# Sync from remote registries
node dist/cli.js packages sync npm --limit 100000 --partial --storage sqlite
node dist/cli.js packages sync pypi --partial --storage json
node dist/cli.js packages sync cargo --partial --storage sqlite
node dist/cli.js packages sync gomod --partial --storage sqlite
node dist/cli.js packages sync maven --limit 1000 --partial --storage json

# Status and checks
node dist/cli.js packages status
node dist/cli.js packages check npm react
node dist/cli.js packages sync-config --config ~/.vibeguard/config.json --storage sqlite
```

### Storage Modes

| Mode | Description |
|------|-------------|
| `auto` | SQLite when Node supports `node:sqlite`, otherwise JSON |
| `sqlite` | `~/.vibeguard/packages.db` |
| `json` | `~/.vibeguard/package-cache.json` + gzip-compressed index |

### Refresh Behavior

Configured refreshes persist registry ETag/Last-Modified metadata. Conditional requests return `304 Not Modified` to refresh timestamps without re-downloading. npm `_all_docs` sources support `_changes` incremental sync for additions/removals.

VSCode starts a background package-cache sync on startup. With lightweight mode, it builds the quick partial index first, rechecks open documents, then continues with the full index. The status bar shows current tier, registry, and completion percentage.

## Ignore Rules

VibeGuard reads `~/.vibeguard/ignore-rules.yml` by default. Ignored findings remain visible as dismissed items but do not create diagnostics or fail the CLI threshold.

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

VSCode ignore actions ask for a reason before writing a rule. Standard reasons: `False positive`, `Not an issue`, `Internal package`, plus custom.

## Custom Rules

Teams can add local YAML rules without rebuilding:

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

Use `--custom-rules ./vibeguard-rules.yml` in CLI, `custom_rules` in config, or `vibeguard.customRules` in VSCode. Private-dashboard admins can also save project-scoped rules through `Project integrations`. Custom findings use rule IDs like `custom.company_public_s3_acl`.

## Semgrep Export

```bash
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
semgrep --config vibeguard-semgrep.yml .
```

Exported YAML keeps each VibeGuard rule ID in `metadata.vibeguard.rule_id` for result mapping. Provider-specific secret signatures are exported directly; contextual high-entropy detection is approximated as conservative regex.

## Findings Storage

CLI and VSCode scans persist to `~/.vibeguard/findings.db` (SQLite) by default. 100 MB on-disk budget with automatic compaction — oldest scan history first, then audit events. `findings status` shows current footprint.

GitHub Action scans default to `store_findings: false` so CI jobs don't write local history unless requested.

The private dashboard records OIDC sign-in/out, sensitive views, authorization denials, and audit events in the same database. `findings audit` is the local operator view; `/api/audit` requires the dashboard `admin` role.

## Scope Notes

The Rust LSP migration has started with a standalone `tower-lsp` native L1 server in [`rust-lsp/`](rust-lsp/). It publishes diagnostics for bundled hallucination seeds, provider signatures, high-entropy secrets, unsafe configurations, and AI error patterns. Returns standard LSP quick fixes for safe npm replacements, full-index-confirmed package names, and mechanical config changes.

The Node LSP remains the VSCode default while the Rust service reaches parity with package-cache sync, remote verification, all registry parsers, L2/L3 scheduling, and persisted findings. Both use the same rule IDs where native coverage exists.

**Environment overrides:**

| Variable | Purpose |
|----------|---------|
| `VIBEGUARD_NATIVE_IGNORE_RULES_PATH` | Override ignore-rules path |
| `VIBEGUARD_NATIVE_PACKAGE_SQLITE_PATH` | Override package SQLite path |
| `VIBEGUARD_NATIVE_PACKAGE_INDEX_PATH` | Override package index path |
| `VIBEGUARD_NATIVE_LSP_PATH` | Use native Rust LSP in JetBrains |

```bash
cargo run --manifest-path rust-lsp/Cargo.toml -- --stdio
```

### Marketplace Release

The `Marketplace Release` workflow packages both editor extensions on manual dispatch. Pushing a version tag (`v0.1.0`) publishes to each configured marketplace after version consistency checks; when a publishing credential is absent, the workflow keeps the packaged artifact and emits a warning instead of failing the release build.

**Required secrets:** `VSCE_PAT` and `JETBRAINS_MARKETPLACE_TOKEN` as GitHub repository secrets.

## Contributing

Contributions are welcome!

- **Report bugs** — [Open an issue](https://github.com/vibeguard/vibeguard/issues/new?labels=bug&template=bug.md)
- **Request features** — [Start a discussion](https://github.com/vibeguard/vibeguard/discussions)
- **Submit PRs** — Fork, create a feature branch, open a pull request
- **Improve docs** — Fix typos, add examples, clarify explanations

```bash
git clone https://github.com/vibeguard/vibeguard.git
cd vibeguard
nvm use          # Node.js 22 LTS
npm install
npm run build
npm test
```

Ensure all tests pass and `npm run lint` is clean before submitting a PR. Development uses Node.js 22 LTS (Node 24 has an intermittent V8 shutdown issue with Tree-sitter WASM + SQLite tests).

## License

[MIT](LICENSE) © 2026 VibeGuard contributors

## Acknowledgements

- [Tree-sitter](https://tree-sitter.github.io/) — incremental parsing for L2 SAST
- [tower-lsp](https://github.com/silvansilvestri/tower-lsp) — Rust LSP framework
- [esbuild](https://esbuild.github.io/) — fast bundling
- All the amazing [contributors](https://github.com/vibeguard/vibeguard/graphs/contributors)

---

<div align="center">

<sub>Built with care for developers who ship AI-generated code.</sub>

<sub>If VibeGuard helps you, consider [starring the repo](https://github.com/vibeguard/vibeguard/stargazers) or [sponsoring](https://github.com/sponsors/vibeguard).</sub>

</div>

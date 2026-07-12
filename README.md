<div align="center">

<h1>VibeGuard</h1>

<p><strong>IDE-first security scanner for AI-generated code</strong></p>

<p><em>Catch what AI missed — hallucinated packages, hardcoded secrets, unsafe configs, and common AI coding mistakes — right in your editor, in real time.</em></p>

<p>
  <a href="https://github.com/vibeguard/vibeguard/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/vibeguard/vibeguard/ci.yml?branch=main&logo=github&label=CI" alt="CI"></a>
  <a href="https://github.com/vibeguard/vibeguard/releases"><img src="https://img.shields.io/github/v/release/vibeguard/vibeguard?display_name=tag&logo=github" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/vibeguard/vibeguard?color=blue" alt="License"></a>
  <a href="https://github.com/vibeguard/vibeguard/stargazers"><img src="https://img.shields.io/github/stars/vibeguard/vibeguard?style=social" alt="Stars"></a>
</p>

<p>
  <img src="https://img.shields.io/badge/VSCode-1.92+-007ACC?logo=visualstudiocode&logoColor=white" alt="VSCode">
  <img src="https://img.shields.io/badge/JetBrains-2025.2+-000000?logo=jetbrains&logoColor=white" alt="JetBrains">
  <img src="https://img.shields.io/badge/Node.js-22%20LTS-339933?logo=node.js&logoColor=white" alt="Node.js 22 LTS">
  <img src="https://img.shields.io/badge/Rust-LSP%20Preview-CE422B?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" alt="Docker">
</p>

---

</div>

## What is VibeGuard?

VibeGuard is an IDE-first security scanner for AI-generated code. It focuses on the mistakes AI tools commonly introduce while you are coding:

- **Hallucinated package names** — catches non-existent npm/PyPI/Cargo/Go/Maven packages
- **Hardcoded secrets** — detects API keys, tokens, and credentials left in source
- **Unsafe framework configuration** — flags debug mode, wildcard CORS, disabled TLS, etc.
- **Insecure coding patterns** — identifies injection, XSS, SSRF, path traversal, and more

## Key Features

| Feature | Description |
|---------|-------------|
| **VSCode Extension** | Real-time diagnostics with a findings sidebar |
| **JetBrains Plugin** | Bundled LSP server for supported JetBrains IDEs |
| **L1 Hallucination Detector** | Package checks across npm/PyPI/Cargo/Go/Maven, Java class imports, hardcoded secrets, loose config, and 31 AI error patterns |
| **L2 Tree-sitter SAST** | JS/TS/Python injection, XSS, SSRF, deserialization, redirects, info leakage + Java JDBC/process/deserialization checks |
| **L3 Semantic Analysis** | DeepSeek, Claude, OpenAI-compatible, local Ollama, or VibeGuard Pro — with local heuristic fallback |
| **Package Cache** | Offline seed mode + optional remote checks for 5 registries |
| **SQLite History** | Local scan history in `~/.vibeguard/findings.db` |
| **CLI Scanner** | Local and CI usage with JSON/SARIF/Markdown output |
| **Shared Config** | `~/.vibeguard/config.json` defaults for CLI and VSCode |

## Table of Contents

- [Architecture](#architecture)
- [Development](#development)
- [JetBrains Plugin](#jetbrains-plugin)
- [Docker](#docker)
- [Team Dashboard](#team-dashboard)
- [Pro Subscription](#pro-subscription)
- [CLI](#cli)
- [Configuration](#configuration)
- [Findings Storage](#findings-storage)
- [Package Index](#package-index)
- [GitHub Action](#github-action)
- [Semgrep Export](#semgrep-export)
- [Ignore Rules](#ignore-rules)
- [Custom Rules](#custom-rules)
- [LSP Server](#lsp-server)
- [VSCode Integration](#vscode-integration)
- [Scope Notes](#scope-notes)
- [Contributing](#contributing)
- [License](#license)

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

**Three-layer detection model:**

| Layer | What | Speed | How |
|-------|------|-------|-----|
| **L1** | Hallucinated packages, secrets, config, AI patterns | < 50ms | Regex + entropy + seed catalog |
| **L2** | SQL injection, XSS, SSRF, path traversal, etc. | < 2s | Tree-sitter WASM AST analysis |
| **L3** | Missing auth/rate-limit/validation, semantic gaps | < 5s | LLM (DeepSeek/Claude/OpenAI/Ollama/Pro) + local heuristics |

## Development

```bash
nvm use
npm install
npm run build
npm test
```

Development, CI, and the Docker image use **Node.js 22 LTS**. Node.js 24.14.1 has an intermittent V8 shutdown failure when this project's Tree-sitter WASM and experimental SQLite tests run together; use Node 22 for test and release work until that runtime regression is resolved.

To try the extension in VSCode, open this folder in VSCode and run the extension host from the debugger after building.

## JetBrains Plugin

The JetBrains module reuses `vibeguard-lsp --stdio`, so its diagnostics and mechanical quick fixes match the CLI and VSCode extension. It targets JetBrains commercial IDEs with the LSP API, starting from the **2025.2** platform release.

```bash
cd jetbrains
./gradlew buildPlugin
```

The distribution ZIP is written to `jetbrains/build/distributions/`. Node.js 18+ is required at runtime; use `VIBEGUARD_NODE_PATH` or `VIBEGUARD_LSP_PATH` to override the Node executable or LSP script in managed environments.

To try the limited native Rust L1 preview instead, build `rust-lsp` and set `VIBEGUARD_NATIVE_LSP_PATH` to its executable (or set the `vibeguard.native.lsp.path` Java system property). It takes precedence over the Node settings; leave it unset for the default full Node service. See [jetbrains/README.md](jetbrains/README.md) for the current native coverage, supported file types, and Windows instructions.

Watch the [14-second CLI demo](media/vibeguard-demo.mp4) for a real scan of the deliberately unsafe [demo sample](demo/unsafe-ai-sample.ts).

## Marketplace Release

The `Marketplace Release` workflow packages both editor extensions on every manual dispatch and uploads the VSIX and JetBrains ZIP as workflow artifacts. Pushing an exact version tag such as `v0.1.0` additionally publishes those packages after checking that `package.json` and `jetbrains/build.gradle.kts` use the same version.

**Required secrets:** `VSCE_PAT` and `JETBRAINS_MARKETPLACE_TOKEN` as GitHub repository secrets. Neither token is stored in the repository or used by normal CI.

Use the Gradle property `-PjetbrainsChannel=eap` to publish a non-default JetBrains Marketplace channel when running the publish task outside the workflow.

## Docker

The Docker image packages the CLI, LSP bundle, and Tree-sitter WASM grammars for a reproducible CI or private deployment runtime. Git is included so `ai-code-scan` can inspect repository history.

```bash
docker build -t vibeguard:local .
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --fail-on high
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --mode ai-code-scan --ai-detection aggressive
```

## Team Dashboard

`findings serve` turns the stored findings history into a deployable team dashboard with developer risk, rule, severity, dismissal, trend, and opt-in anonymous feedback-signal views. It listens on `127.0.0.1:8787` by default.

> **Warning:** Use `--host 0.0.0.0` only behind a private network or reverse proxy.

### Service Token (Small Private Deployment)

An environment-backed service token remains available as an emergency administrator credential. Do not put that token in a CI log or source file, and do not leave it in a bookmarked or shared URL.

```bash
VIBEGUARD_DASHBOARD_TOKEN=replace-with-a-long-random-value \
  node dist/cli.js findings serve --db ~/.vibeguard/findings.db --token-env VIBEGUARD_DASHBOARD_TOKEN
```

### OIDC (Enterprise Deployment)

For enterprise deployments, use a standards-based OpenID Connect provider. VibeGuard uses authorization code flow with PKCE, validates signed ID tokens against the provider JWKS, and stores only a short-lived signed HttpOnly dashboard session.

Register `<public-url>/auth/callback` as the provider callback URL. `--public-url` must be a bare HTTPS origin; HTTP is accepted only for localhost development.

```bash
export VIBEGUARD_OIDC_ISSUER=https://id.example.com
export VIBEGUARD_OIDC_CLIENT_ID=vibeguard-dashboard
export VIBEGUARD_OIDC_CLIENT_SECRET=replace-with-provider-secret
export VIBEGUARD_OIDC_SESSION_SECRET=replace-with-at-least-32-random-characters

node dist/cli.js findings serve --db ~/.vibeguard/findings.db --host 0.0.0.0 \
  --public-url https://guard.example.com --secure-cookies \
  --oidc-issuer-env VIBEGUARD_OIDC_ISSUER \
  --oidc-client-id-env VIBEGUARD_OIDC_CLIENT_ID \
  --oidc-client-secret-env VIBEGUARD_OIDC_CLIENT_SECRET \
  --oidc-session-secret-env VIBEGUARD_OIDC_SESSION_SECRET \
  --oidc-role-claim groups \
  --oidc-role security-reviewers=analyst \
  --oidc-role platform-admins=admin
```

**Role mapping:**

| Role | Access |
|------|--------|
| `viewer` (default) | `/`, `/api/summary` |
| `analyst` | + `/api/findings`, `/api/compliance` |
| `admin` | + `/api/findings?all=true`, `/api/audit` |

OIDC supports a dotted role claim path, such as `realm_access.roles`. An unmapped identity receives `none` access by default; add `--oidc-default-role viewer` only when every signed-in identity should see dashboard summaries. `/api/session` exposes the current identity and effective role. `/healthz` intentionally remains unauthenticated for container orchestration.

The service-token flow grants `admin` access. A browser can authenticate it through a reverse proxy, or a one-time `/?token=<service-token>` visit sets an HttpOnly, SameSite=Strict token cookie for that dashboard origin; it is also marked `Secure` whenever the public origin uses HTTPS, then redirects to the same URL without the token. Prefer OIDC for normal users.

### Docker Deployment

Mount the directory that holds `findings.db` and publish the dashboard port:

```bash
docker run --rm -p 8787:8787 -e VIBEGUARD_DASHBOARD_TOKEN \
  -v "$PWD/.vibeguard:/data" vibeguard:local \
  findings serve --db /data/findings.db --host 0.0.0.0 --token-env VIBEGUARD_DASHBOARD_TOKEN
```

### Private Deployment Compose

`deploy/compose.yaml` packages the private dashboard as a long-running Compose service with a persistent SQLite volume, health check, disabled privilege escalation, dropped Linux capabilities, and a default `127.0.0.1` host binding. Its required environment-variable names and non-secret defaults are documented in `deploy/.env.example`.

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
docker compose --env-file deploy/.env -f deploy/compose.yaml logs -f dashboard
```

To use the enterprise OIDC flow, place the dashboard behind an HTTPS reverse proxy and merge the OIDC override:

```bash
docker compose --env-file deploy/.env \
  -f deploy/compose.yaml -f deploy/compose.oidc.yaml up -d --build
```

The service-token and CI ingest-token values remain separate in both configurations. Keep the default loopback bind unless a private reverse proxy or network policy is in front of the service.

The Compose service keeps anonymous false-positive collection disabled by default. To enable the privacy-minimized `POST /api/telemetry/false-positive` collector, set `VIBEGUARD_TELEMETRY_COLLECTION=true` and, if needed, `VIBEGUARD_TELEMETRY_MAX_EVENTS_PER_MINUTE=60` in `deploy/.env`. The container entrypoint adds the corresponding CLI flags only for `findings serve`; normal scanner containers are unaffected. Keep this endpoint behind TLS when it is reachable beyond localhost, and use it only with explicitly opted-in clients.

### Central CI Ingestion

Private dashboards can receive scan history from CI without sharing the dashboard administrator token. Enable a separate ingest token on the dashboard, keep the dashboard behind TLS in production, and give only that ingest token to CI.

The `POST /api/ingest` endpoint accepts only JSON scan payloads with bounded fields, a 5 MiB body limit, and up to 10,000 findings per upload by default. It does not accept dashboard cookies or OIDC sessions, and successful uploads are recorded as `findings.ingested` audit events without credentials.

Every upload may carry a stable project identifier. Use `--findings-project` from a generic CLI environment; the GitHub Action defaults it to `GITHUB_REPOSITORY` and exposes `findings_project` only for overrides.

**Project-scoped credentials** — An administrator can issue one project-scoped ingest credential through the protected `/api/projects` endpoint. The raw token is returned only when it is created or rotated; SQLite stores only its SHA-256 digest. A project token can upload only when `scan.project` exactly matches its assigned project, and revocation immediately rejects further uploads. The legacy global ingest token remains available as a break-glass or migration credential.

```bash
# Create: returns { project, token, createdAt, updatedAt, created } once.
curl --fail-with-body -X POST https://guard.example.com/api/projects \
  -H "Authorization: Bearer $VIBEGUARD_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"project":"acme/payments-api"}'

# Rotate or revoke.
curl --fail-with-body -X POST https://guard.example.com/api/projects \
  -H "Authorization: Bearer $VIBEGUARD_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"project":"acme/payments-api","rotate":true}'

curl --fail-with-body -X DELETE 'https://guard.example.com/api/projects?project=acme%2Fpayments-api' \
  -H "Authorization: Bearer $VIBEGUARD_DASHBOARD_TOKEN"
```

Dashboard administrators can manage the same credential lifecycle from the `Project integrations` link in the protected dashboard. The page displays each newly created or rotated token only once, provides a copy action without browser storage, and renders a copyable GitHub Action fragment that references the dedicated CI secret without embedding the raw token. The same page also manages per-project custom-rule YAML. Rules are parsed before saving, limited to 100 rules and 256 KiB per project, and can be downloaded only by a dashboard administrator, the break-glass ingest credential, or the matching project credential. CI receives the rules through the separate `GET /api/project-rules/download?project=<id>` endpoint; a missing project rule set is treated as intentionally unconfigured unless the workflow marks it required.

```bash
export VIBEGUARD_DASHBOARD_TOKEN=replace-with-break-glass-token
export VIBEGUARD_FINDINGS_INGEST_TOKEN=replace-with-dedicated-ci-token

node dist/cli.js findings serve --db ~/.vibeguard/findings.db --host 0.0.0.0 \
  --token-env VIBEGUARD_DASHBOARD_TOKEN \
  --ingest-token-env VIBEGUARD_FINDINGS_INGEST_TOKEN
```

The CLI can then upload one completed scan. Upload failures remain warnings by default so an unavailable dashboard does not hide scanner results; add `--findings-upload-required` when the centralized record is a required CI gate.

```bash
VIBEGUARD_FINDINGS_INGEST_TOKEN=replace-with-dedicated-ci-token \
  node dist/cli.js scan . --no-store-findings \
  --findings-endpoint https://guard.example.com/api/ingest \
  --findings-token-env VIBEGUARD_FINDINGS_INGEST_TOKEN \
  --findings-project acme/payments-api \
  --findings-upload-required
```

## Pro Subscription

The `vibeguard` L3 provider uses the official hosted service and its server-enforced Pro, Team, or Enterprise allowance. It does not replace the free BYOK paths: DeepSeek, Claude, OpenAI-compatible endpoints, and local Ollama remain available without a VibeGuard subscription.

Store the Pro credential:

| Environment | Method |
|-------------|--------|
| CI / Docker | `VIBEGUARD_PRO_API_KEY` env var |
| CLI / shared LSP | `vibeguard llm-key set --provider vibeguard --from-env VIBEGUARD_PRO_API_KEY` |
| VSCode | `VibeGuard: Set LLM API Key` with provider `vibeguard` (held in SecretStorage) |

```bash
export VIBEGUARD_PRO_API_KEY=replace-with-pro-credential
node dist/cli.js llm-key set --provider vibeguard --from-env VIBEGUARD_PRO_API_KEY
node dist/cli.js scan src --l3 --llm-provider vibeguard
node dist/cli.js subscription status
```

The default service origin is `https://api.vibeguard.dev/v1`. Private service deployments can set `VIBEGUARD_PRO_API_BASE_URL`; it must use HTTPS except for localhost development. The VSCode extension and LSP deliberately ignore a workspace-level `llmBaseUrl` for the hosted provider, so a repository cannot redirect a stored Pro credential.

The hosted contract is OpenAI-compatible for `POST /chat/completions` and exposes `GET /account/usage` for the status command. The usage response contains `plan`, `status`, optional `features`, and `usage.l3_requests` with `used`, `limit`, and optional `reset_at`. Billing, credit checks, and request limits remain server-side; the client never writes the Pro credential into `config.json`.

## CLI

### Basic Usage

```bash
npm run build
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

`--l3` enables semantic endpoint checks. When a configured provider has credentials, VibeGuard calls the LLM with detected framework, function, and route context and expects structured JSON findings. Before source is sent to a remote provider, high-confidence secret literals are replaced with a placeholder, including complete private-key blocks, and only the source filename is included rather than its directory path. Local Ollama analysis keeps the source local and does not apply this transport redaction.

Without credentials, VibeGuard falls back to conservative local heuristics for missing authentication, rate limiting, input validation, parameterized database queries, IO error handling, and output encoding around Express, FastAPI/Flask, Django, and Spring MVC route handlers.

**Framework coverage:**

- **Django** — resolves same-file `urlpatterns` `path`/`re_path` entries and standalone `views.py` function views that return Django/DRF responses; recognizes common auth, rate-limit, HTTP-method, and form-validation decorators
- **Spring MVC** — includes class-level `@RequestMapping` prefixes and method-level mappings; recognized `@PreAuthorize`, `@RateLimiter`, `@Valid`, and `try`/`catch` controls suppress the corresponding missing-control finding
- **Express** — recognizes same-file `app.use`/`router.use` authentication and rate-limit middleware; controls registered for a path prefix apply only to matching routes

An LLM may optionally return a replacement for the exact evidence snippet; VibeGuard validates its range, rejects fenced/diff-like output, and exposes it as a non-preferred Quick Fix for review.

When L3 recognizes Express, Python, or Spring route handlers, it sends bounded handler blocks with their original file line numbers instead of blindly truncating the file prefix. The prompt asks the model to trace request-derived values through aliases and helper calls to security-sensitive sinks, and treats comments, strings, and all source text as untrusted data rather than instructions.

**Provider controls:**

```bash
node dist/cli.js scan src --l3 --llm-provider deepseek --llm-model deepseek-v4-flash
node dist/cli.js scan src --l3 --llm-provider claude --llm-api-key-env ANTHROPIC_API_KEY
node dist/cli.js scan src --l3 --llm-provider openai --llm-base-url https://api.openai.com/v1
node dist/cli.js scan src --l3 --llm-provider local --llm-base-url http://localhost:11434
node dist/cli.js llm-key set --provider deepseek --from-env DEEPSEEK_API_KEY
node dist/cli.js llm-key status --provider deepseek
```

Remote LLM base URLs must use HTTPS. HTTP is accepted only for `localhost`, `127.0.0.1`, or IPv6 loopback development endpoints; redirects, URL credentials, query parameters, and fragments are rejected before source or API credentials are sent.

### Detection Coverage

**L1 — Secret scanner** combines provider-specific signatures for keys and tokens, sensitive assignment context (`apiKey`, `clientSecret`, `Authorization`, `webhookSecret`), Shannon-entropy scoring for random-looking literals, and false-positive filters for placeholders, hashes, fixtures, UUIDs, and normal encoded data. High-confidence JS/TS and Python secret assignments include quick fixes that replace committed literals with environment-variable reads.

**L1 — AI pattern library** covers common generated-code mistakes: placeholder credentials, unsafe JWT handling, wildcard CORS with credentials, disabled TLS verification, weak password hashing, plaintext password comparison, insecure random token generation, placeholder framework secrets, and public object-storage ACLs.

**L2 — SAST** covers high-confidence SQL injection, XSS, SSRF, path traversal, unsafe deserialization, command injection, open redirect, and error-detail leakage patterns:

| Pattern | Coverage |
|---------|----------|
| SSRF | Fetch, Axios, Node HTTP(S), Requests, HTTPX, Java `RestTemplate`, `WebClient`, JDK `HttpRequest`, OkHttp `Request.Builder` |
| Command injection | Node `exec`/`execSync`, shell-enabled `spawn`/`spawnSync`/`execFile`, Python execution APIs |
| Path traversal | Node `fs`/`fs.promises` reads/writes/appends/streams/deletes, Java `Files`/`Paths`/`File` |
| Open redirect (Java) | Servlet, `RedirectView`, `redirect:` targets |
| Error leakage (Java) | 5xx Servlet or Spring responses returning exception messages |

High-confidence `innerHTML` and unsafe `yaml.load()` findings include mechanical quick fixes.

### Findings Management

```bash
node dist/cli.js findings status
node dist/cli.js findings list --limit 20
node dist/cli.js findings list --all --json
node dist/cli.js findings summary --days 30 --top 10
node dist/cli.js findings summary --json
node dist/cli.js findings dashboard --days 30 --top 10 --output vibeguard-dashboard.html
node dist/cli.js findings compliance --framework all --days 90 --output vibeguard-compliance-report.md
node dist/cli.js findings audit --limit 100
node dist/cli.js findings prune --days 30
node dist/cli.js scan . --findings-db ~/.vibeguard/findings.db
node dist/cli.js scan . --no-store-findings
```

`findings summary` aggregates stored history by severity, type, top detection rules, dismissal reason, git author, daily trend, and the active-finding delta between the latest two scans. It also records per-rule false-positive counts and rates only when dismissals use the standard `False positive` reason. The delta separates introduced, resolved, and persistent risks.

`findings dashboard` writes a standalone HTML dashboard with trend, author, dismissal-reason, scan-delta, and rule-feedback data, suitable for CI artifacts or offline review. VSCode users can run `VibeGuard: Export Findings Dashboard` to generate and open it from the command palette.

`findings compliance` writes a source-free Markdown evidence report for `soc2`, `iso27001`, or both. It maps scan history to control objectives, open mapped findings, trend cadence, top rules, and dismissal reasons. Use `--json` to emit the same evidence shape for a GRC system, and `/api/compliance` from the protected team dashboard for an analyst-role JSON view.

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
    "lightweight_mode": true,
    "background_full_sync": true
  },
  "telemetry": false
}
```

Relative `custom_rules` paths resolve from the config file directory. Use `--config path/to/config.json` for a project-specific file or `--no-config` to run with built-in defaults only.

### Telemetry

Set `telemetry` to `true` only when you want to contribute anonymous false-positive feedback. VibeGuard sends an event only after a user selects the standard `False positive` dismissal reason. The event includes a truncated SHA-256 rule fingerprint, finding type/layer/severity, and ignore scope; it never includes source code, evidence, package names, file paths, line numbers, project identifiers, authors, finding IDs, or free-form reasons. Delivery failures do not block scans or ignore actions.

The default destination is the VibeGuard HTTPS telemetry endpoint; `VIBEGUARD_TELEMETRY_ENDPOINT` can override it for approved localhost development or a private HTTPS collector. A self-hosted dashboard can act as that collector only when started with `--telemetry-collection`; it is disabled by default.

### Deduplication

`dedup_with_existing_tools` dismisses duplicate L2 findings when nearby SonarQube, Snyk, Semgrep, or CodeQL annotations already cover the same issue. Override it in the CLI with `--dedup-existing-tools` or `--no-dedup-existing-tools`.

### Ignored Findings

Use `ignored_findings` for exact finding-id dismissals:

```bash
node dist/cli.js config ignore-finding vg_12345678
node dist/cli.js config unignore-finding vg_12345678
```

### LLM API Key Storage

`llm_api_key` must remain `null`; VibeGuard rejects plaintext keys in config JSON.

| Environment | Storage Method |
|-------------|----------------|
| VSCode | SecretStorage via `VibeGuard: Set LLM API Key` |
| CLI / shared LSP | `vibeguard llm-key set --provider <provider> --from-env <ENV_VAR>` — Windows DPAPI, macOS Keychain, or Linux Secret Service |
| Fallback | `VIBEGUARD_LLM_CREDENTIAL_PIN` (8+ chars) → scrypt + AES-256-GCM |

`llm-key delete` removes either storage form and `llm-key status` reports only whether one exists. Environment variables continue to take precedence, which keeps CI and one-off scans non-interactive.

## Findings Storage

CLI and VSCode scans persist scan runs and findings to `~/.vibeguard/findings.db` by default. Stored dismissed findings remain queryable for audit trails, while normal diagnostics and fail thresholds still use only active findings.

The database has a **100 MB on-disk budget** that includes SQLite WAL sidecar files. When exceeded, VibeGuard compacts the database and removes the oldest scan history first, then the oldest audit and anonymous-feedback history only when necessary. `findings status` and `findings summary` show the current footprint and budget; `findings prune` remains available when an operator needs a specific retention period.

CLI and VSCode scans record the latest git author for files with findings when git history is available, so the summary and dashboard can surface developer risk hotspots.

The private dashboard records successful OIDC sign-ins/sign-outs, sensitive findings and compliance views, audit-log views, and authenticated authorization denials in the same SQLite database. Audit metadata is bounded and filters keys such as tokens, cookies, authorization headers, passwords, and provider codes. `findings audit` is the local operator view; `/api/audit` requires the dashboard `admin` role. `findings prune` applies the selected retention cutoff to both scan history and audit events.

GitHub Action scans default to `store_findings: false` so CI jobs do not write local history unless explicitly requested.

## Package Index

The scanner can use a local package-name index before falling back to the seed catalog or remote registry checks. Partial indexes act as an existence cache; full indexes can also prove that a package is missing and suggest close package names for typos or slopsquatting-like hallucinations.

**Default modes:**

| Environment | Default | Behavior |
|-------------|---------|----------|
| VSCode / shared LSP | `remote` | Edit-time L1 uses local seed/index first, then verifies unresolved packages asynchronously |
| CLI / Action | `seed` | Deterministic offline scans |

JavaScript and TypeScript only treat code-region `import`, `export`, and `require` expressions as package references, so examples in comments and string literals remain quiet. Explicit local npm dependency protocols (`workspace:`, `file:`, `link:`, and `portal:`) are never checked against the public npm registry.

### Supported Registries

| Registry | Source | Notes |
|----------|--------|-------|
| npm | `_all_docs` | Conditional refresh with `_changes` incremental sync |
| PyPI | Simple API | Recognizes imports, manifests, `pip install`, notebooks, Dockerfiles, YAML CI |
| Cargo | crates.io | Resolves aliases to actual crate names; skips `path`/`git`/custom `registry` sources |
| Go modules | Go module index | — |
| Maven | Maven Central search | Verifies exact Java/Kotlin import classes via class index |

For `pyproject.toml`, VibeGuard checks `[project]` dependencies, `[project.optional-dependencies]`, `[build-system]` requirements, and Poetry dependency/group sections. Project metadata such as names, descriptions, authors, and version values is not interpreted as a PyPI package.

Java and Kotlin dependency parsing supports Maven POM files, Gradle build scripts, Gradle `*.versions.toml` catalogs, plus exact external class imports. Java SE namespaces, Kotlin runtime, and Android namespaces are excluded from Maven class lookup. Kotlin aliases are resolved to their original class; wildcard imports and lower-case top-level function imports are intentionally skipped.

### CLI Commands

```bash
# Import a local package list
node dist/cli.js packages import npm ./npm-packages.txt --partial --storage sqlite
node dist/cli.js packages import pypi ./pypi-packages.json --full --storage json
node dist/cli.js packages import cargo ./cargo-crates.txt --partial --storage sqlite

# Sync from remote registries
node dist/cli.js packages sync npm --limit 100000 --partial --storage sqlite
node dist/cli.js packages sync pypi --partial --storage json
node dist/cli.js packages sync cargo --limit 100 --partial --storage sqlite
node dist/cli.js packages sync gomod --partial --storage sqlite
node dist/cli.js packages sync maven --limit 1000 --partial --storage json

# Sync from config and check status
node dist/cli.js packages sync-config --config ~/.vibeguard/config.json --storage sqlite
node dist/cli.js packages status
node dist/cli.js packages check npm react
```

Supported import formats: newline-delimited package names, JSON arrays, `{ "packages": [...] }`, and npm `_all_docs` style `{ "rows": [{ "id": "package" }] }`.

### Refresh Behavior

Configured refreshes persist registry ETag and Last-Modified metadata with the local index. Once an index is due, VibeGuard sends conditional requests only to the same registry URL; a `304 Not Modified` response refreshes the local timestamp without downloading or re-importing the package list.

For npm `_all_docs` sources, both `packages sync npm` and the first configured full sync store a conservative replication sequence. Later stale refreshes consume same-source `_changes` batches, applying package additions and removals without downloading the complete index. Manual forced refreshes, changed registry URLs, and mirrors that do not expose a compatible change stream automatically use the full-refresh path.

When a package is absent from a full local index, VibeGuard combines curated seed suggestions with fuzzy matches from the synced index. The first close match is exposed as an editor/CLI fix when the import specifier can be safely replaced.

`packages sync-config` reads `package_cache.languages`, `package_cache.update_interval`, and `package_cache.lightweight_mode` from config.json. It skips fresh registries, refreshes stale registries, and upgrades partial indexes when lightweight mode is disabled. Use `--force` to refresh everything now, `--limit` to override the lightweight target, and `--url registry=URL` for a registry mirror or test fixture.

### VSCode Integration

The VSCode extension starts a background package-cache sync on startup. On first run it shows a one-time cold-start note that secret, config, and AI-pattern checks are active immediately while the package-name cache prepares hallucinated-package detection.

With lightweight mode enabled, it first builds the quick partial index and immediately rechecks open documents, then continues with the full index in Tier 2. Set `package_cache.background_full_sync` or `vibeguard.packageCacheBackgroundFullSync` to `false` to retain only the quick index. It prioritizes package managers detected in the current workspace, then queues the other configured registries in the same background sync. The status bar identifies the current tier, registry, and completion percentage.

Run `VibeGuard: Sync Package Cache` from the command palette to force a refresh of the configured tier.

### Storage Modes

| Mode | Description |
|------|-------------|
| `auto` | Use SQLite when the current Node runtime supports `node:sqlite`, otherwise JSON |
| `sqlite` | Store in `~/.vibeguard/packages.db` |
| `json` | Store in `~/.vibeguard/package-cache.json` + gzip-compressed `~/.vibeguard/package-index.json.gz`; legacy `package-index.json` files are read automatically and migrate on the next index write |

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
      VIBEGUARD_FINDINGS_INGEST_TOKEN: ${{ secrets.VIBEGUARD_FINDINGS_INGEST_TOKEN }}
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
          pr_review_comments: true
          pr_review_comment_limit: 20
          config: .vibeguard/config.json
          dedup_existing_tools: true
          store_findings: true
          # findings_project: acme/security-platform
          findings_endpoint: https://guard.example.com/api/ingest
          findings_token_env: VIBEGUARD_FINDINGS_INGEST_TOKEN
          findings_rules_endpoint: https://guard.example.com/api/project-rules/download?project=acme%2Fsecurity-platform
          findings_rules_required: true
          findings_upload_required: true
          dashboard: true
          dashboard_path: vibeguard-dashboard.html
          compliance: true
          compliance_path: vibeguard-compliance-report.md
          compliance_framework: all
          compliance_days: 90
          ignore_rules: .vibeguard/ignore-rules.yml
          custom_rules: .vibeguard/custom-rules.yml
          package_index: .vibeguard/package-index.json.gz
          storage: auto
      - uses: actions/upload-artifact@v4
        if: always() && steps.vibeguard.outputs.dashboard_path != ''
        with:
          name: vibeguard-dashboard
          path: ${{ steps.vibeguard.outputs.dashboard_path }}
      - uses: actions/upload-artifact@v4
        if: always() && steps.vibeguard.outputs.compliance_path != ''
        with:
          name: vibeguard-compliance-evidence
          path: ${{ steps.vibeguard.outputs.compliance_path }}
```

### Package Verification Modes

| Mode | Description |
|------|-------------|
| `seed` | Instant, offline checks against the built-in known-good/known-hallucinated catalog |
| `remote` | Seed + cached remote npm/PyPI/Cargo/Go/Maven verification with 3s timeout and max 5 in-flight requests. Only definitive misses are cached; unavailable/rate-limited responses produce non-blocking warnings |
| `off` | Disables package existence checks |

### PR Feedback

| Option | Description |
|--------|-------------|
| `github_annotations: true` | Emit GitHub workflow annotations |
| `step_summary: true` | Append Markdown report to job summary |
| `pr_comment: true` | Create/update a sticky PR comment |
| `pr_review_comments: true` | Create a single `COMMENT` review with up to `pr_review_comment_limit` findings on changed diff lines (requires `pull-requests: write`, skips existing VibeGuard comments, never includes code evidence) |
| `sarif` | Write SARIF 2.1.0 report for `github/codeql-action/upload-sarif` |
| `markdown` | Keep Markdown report as artifact |

### AI Code Scan Mode

Set `mode: ai-code-scan` to analyze changed files but report only findings that overlap changed lines attributed to AI. VibeGuard parses zero-context diff hunks, uses `git blame` on the checked-out head for line attribution, and reads the blamed commit message only when needed.

| `ai_detection` | Matches |
|-----------------|---------|
| `author` | The blamed author |
| `message` | The blamed commit body or trailers |
| `aggressive` | Either signal + additions of 50+ lines |

When git history or blame cannot be inspected, VibeGuard falls back to a full scan so CI does not silently miss findings.

### Central Rules

Set `findings_rules_endpoint` to the private dashboard's project-rule download endpoint to append centrally managed YAML rules to the scan. The Action uses the same environment-backed project credential, accepts only HTTPS endpoints except loopback HTTP development, does not follow redirects, and never writes the token to output. A `404` means no central rule set is configured; other download failures warn by default or fail the job with `findings_rules_required: true`.

The composite Action sets up Node.js 22 before installing and building VibeGuard, so callers do not need to select a Node version separately.

## Semgrep Export

VibeGuard can export its core AI/security rules to a Semgrep config file. Built-in AI pattern rules are exported from the same rule definitions used by the scanner.

```bash
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
semgrep --config vibeguard-semgrep.yml .
```

The exported YAML keeps each VibeGuard rule id in `metadata.vibeguard.rule_id` so Semgrep results can be mapped back to VibeGuard findings.

**Limitations:** Provider-specific secret signatures are exported directly; contextual high-entropy secret detection is exported as a conservative regex approximation because the full Shannon-entropy and false-positive filtering logic runs inside the VibeGuard scanner.

## Ignore Rules

VibeGuard reads `~/.vibeguard/ignore-rules.yml` by default. Ignored findings remain visible as dismissed items in editor views and JSON output, but they do not create diagnostics or fail the CLI threshold.

VSCode ignore actions ask for a reason before writing a rule. Standard reasons include `False positive`, `Not an issue`, and `Internal package`, with a custom reason option for team-specific context.

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

Use `--custom-rules ./vibeguard-rules.yml` in the CLI, `custom_rules` in `config.json`, `custom_rules` in the Action, or `vibeguard.customRules` in VSCode. Private-dashboard administrators can additionally save a validated project ruleset through `Project integrations` and give CI its `findings_rules_endpoint`; Action scans merge that downloaded ruleset with local custom rules. Custom findings use rule ids like `custom.company_public_s3_acl`, so they can be ignored with the normal ignore-rules.yml flow.

## LSP Server

```bash
npm run build
node dist/lspServer.js --stdio
```

The LSP server publishes VibeGuard diagnostics with the same scanner used by the VSCode extension and CLI.

**Debounce behavior:**

| Event | L1 | L2 | L3 |
|-------|----|----|----|
| Edit | Immediate | 500ms | 2s |
| Save | Immediate | Immediate | Immediate |

`l2DebounceMs` and `l3DebounceMs` can override those values through LSP configuration. Its default `remote` package mode first publishes local L1 findings, then checks unresolved packages after the edit-time delay.

Newly detected critical findings use the standard LSP warning dialog, offering safe mechanical fixes plus line, file, global-rule, and package-name ignores; clients that advertise `window.showDocument.support` also receive a `Manage Ignore Rules` action. Set `showCriticalPopups: false` to disable those alerts.

The server exposes LSP `quickfix` code actions for the same operations, so non-VSCode LSP clients can apply package-name, secret-assignment, config, SAST, and false-positive workflows without leaving the editor. Mechanical quick fixes resolve the current finding on the server and verify its evidence before requesting the edit. L3 generated replacements additionally ask for confirmation and recheck the current document before the workspace edit.

On initialization, the LSP refreshes the shared package-name cache in the background. It reads `package_cache` from the shared config, prioritizes registries identified by dependency manifests at workspace roots, and rechecks open documents' L1 package findings when each tier is updated. Clients that advertise standard LSP `window.workDoneProgress` receive native tier and percentage updates.

**LSP initialization options** (or `workspace/didChangeConfiguration` under `vibeguard`):

- `showCriticalPopups`
- `autoSyncPackageCache`
- `configPath`
- `packageCacheLanguages`
- `packageCacheUpdateInterval`
- `packageCacheLightweightMode`
- `packageCacheBackgroundFullSync`

## VSCode Integration

### Settings

| Setting | Description |
|---------|-------------|
| `vibeguard.enabled` | Enable/disable scanning |
| `vibeguard.scanOnChange` | Scan on document change |
| `vibeguard.scanOnSave` | Scan on document save |
| `vibeguard.configPath` | Path to config file |
| `vibeguard.packageVerification` | `remote` (default), `seed`, or `off` |
| `vibeguard.autoSyncPackageCache` | Auto-sync package cache on startup |
| `vibeguard.packageCacheLanguages` | Registries to sync |
| `vibeguard.packageCacheUpdateInterval` | Sync interval |
| `vibeguard.packageCacheLightweightMode` | Quick partial index first |
| `vibeguard.packageCacheBackgroundFullSync` | Upgrade to full index in background |
| `vibeguard.enableL2` | Enable L2 SAST |
| `vibeguard.l2DebounceMs` | L2 debounce (default 500) |
| `vibeguard.enableL3` | Enable L3 semantic analysis |
| `vibeguard.l3DebounceMs` | L3 debounce (default 2000) |
| `vibeguard.llmProvider` | LLM provider for L3 |
| `vibeguard.llmModel` | LLM model name |
| `vibeguard.llmBaseUrl` | LLM base URL |
| `vibeguard.dedupWithExistingTools` | Dedup with SonarQube/Snyk/Semgrep/CodeQL |
| `vibeguard.storeFindings` | Persist to SQLite |
| `vibeguard.findingsDbPath` | Custom SQLite path |
| `vibeguard.ignoredFindings` | Finding IDs to ignore |
| `vibeguard.customRules` | Custom rules YAML paths |
| `vibeguard.showCriticalPopups` | Show critical finding dialogs |
| `vibeguard.ignoreRulesPath` | Ignore rules YAML path |

### Commands

| Command | Description |
|---------|-------------|
| `VibeGuard: Set LLM API Key` | Store provider key in SecretStorage |
| `VibeGuard: Delete LLM API Key` | Remove stored key |
| `VibeGuard: Show LLM Status` | Display provider and key status |
| `VibeGuard: Show Pro Subscription Status` | Display Pro plan and usage |
| `VibeGuard: Review and Apply All Pro Fixes in Current File` | Multi-select L3 replacements |
| `VibeGuard: Export Findings Dashboard` | Generate HTML dashboard |
| `VibeGuard: Sync Package Cache` | Force cache refresh |
| `VibeGuard: Apply All Safe Fixes in Current File` | Batch L1/L2 mechanical fixes |

### Quick Fixes

VibeGuard publishes diagnostics with quick actions. When a finding has a safe mechanical fix, the editor lightbulb, the Findings sidebar context menu, or an LSP client quickfix can apply it directly.

Before applying a single fix, VSCode verifies the original finding evidence still matches the open document; redacted secret findings are revalidated by regenerating their safe fix from current source without exposing the secret.

**Available fixes:**

- Hallucinated packages — every verified similar-name candidate as individual Quick Fix (best match marked preferred)
- Hardcoded secret assignments → environment-variable reads
- Debug/CORS/host-check toggles
- `yaml.load()` → `yaml.safe_load()`
- SQL f-strings → parameterized `execute()` calls
- `innerHTML` → `textContent`

`VibeGuard: Apply All Safe Fixes in Current File` applies non-overlapping L1/L2 mechanical fixes in one reviewed operation. With VibeGuard Pro, `VibeGuard: Review and Apply All Pro Fixes in Current File` combines mechanical fixes with a multi-select review of L3 replacements; each L3 edit must still match current document evidence before confirmation.

Critical VSCode alerts include a `Learn More` action that opens the finding location and appends its rule, evidence, suggestion, and available fix to the VibeGuard output channel. The extension also exposes ignore actions for the current finding, current file, global rule, or hallucinated package name.

### Edit-Time Scanning

Normal edit-time scans run L1 immediately for fast feedback, then debounce L2 SAST for 500ms by default. Package verification defaults to `remote`: edit-time scans first use local seed/cache results and schedule the remote registry check independently after a 600ms delay, so registry latency does not block diagnostics. Set `vibeguard.packageVerification` to `seed` for offline-only editor checks.

When L3 is enabled, semantic analysis is debounced for 2 seconds after edits by default. The status bar tooltip includes recent scan timing totals and shows a watch marker when a file exceeds the L1/L2/L3 performance budget.

## Scope Notes

The Rust LSP migration has started with a standalone `tower-lsp` native L1 server in [`rust-lsp/`](rust-lsp/). It keeps open documents in memory and publishes diagnostics for:

- Bundled npm, PyPI, Cargo, Go module, and Maven hallucination seeds
- Provider signatures
- Contextual and standalone high-entropy secret literals (with placeholder/hash/fixture filtering)
- JWTs, private-key blocks, credential-bearing database URLs
- Unsafe-configuration rules
- High-confidence AI error patterns (default credentials, disabled TLS, weak token generation, insecure session settings)

It returns standard LSP quick fixes for safe npm seed replacements, full-index-confirmed similar npm package names, and mechanical configuration changes. It persists ignores to the shared `~/.vibeguard/ignore-rules.yml`.

**Environment overrides:**

| Variable | Purpose |
|----------|---------|
| `VIBEGUARD_NATIVE_IGNORE_RULES_PATH` | Override ignore-rules path |
| `VIBEGUARD_NATIVE_PACKAGE_SQLITE_PATH` | Override package SQLite path |
| `VIBEGUARD_NATIVE_PACKAGE_INDEX_PATH` | Override package index path |
| `VIBEGUARD_NATIVE_LSP_PATH` | Use native Rust LSP in JetBrains |
| `vibeguard.native.lsp.path` | Same as above (Java system property) |

Native package extraction is document-type-aware: JavaScript and TypeScript support static, dynamic, re-exported, and CommonJS package references; Python also checks executable `pip install` automation arguments. The native preview supports `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml` (including renamed crates), `go.mod`, Maven POM files, Gradle build scripts, and `*.versions.toml` catalogs.

The Node LSP remains the VSCode default while the Rust service reaches parity with package-cache synchronization and remote verification, all registry parsers, remaining code actions, L2/L3 scheduling, and persisted findings. Both use the same rule IDs where native coverage exists, so the editor integration can move over without changing the user-facing finding contract.

Run the native LSP over stdio:

```bash
cargo run --manifest-path rust-lsp/Cargo.toml -- --stdio
```

## Contributing

Contributions are welcome!

- **Report bugs** — [Open an issue](https://github.com/vibeguard/vibeguard/issues/new?labels=bug&template=bug.md)
- **Request features** — [Start a discussion](https://github.com/vibeguard/vibeguard/discussions)
- **Submit PRs** — Fork the repo, create a feature branch, and open a pull request
- **Improve docs** — Fix typos, add examples, clarify explanations
- **Spread the word** — Star the repo, share with your team

### Development Setup

```bash
git clone https://github.com/vibeguard/vibeguard.git
cd vibeguard
nvm use          # Node.js 22 LTS
npm install
npm run build
npm test
```

Please ensure all tests pass and `npm run lint` is clean before submitting a pull request.

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

# VibeGuard

VibeGuard is an IDE-first security scanner for AI-generated code. It focuses on the mistakes AI tools commonly introduce while you are coding: hallucinated package names, hardcoded secrets, unsafe framework configuration, and high-confidence insecure coding patterns.

This repository implements the core `VibeGuard-PRD.md` roadmap through L3 and the initial Pro subscription client:

- VSCode extension shell with real-time diagnostics and a findings sidebar
- JetBrains plugin module that starts the same bundled LSP server for supported source files
- L1 scanner for npm/PyPI/Cargo/Go/Maven hallucinated packages, including exact external Java class imports, hardcoded secrets, loose config, and expanded AI error patterns
- Tree-sitter WASM-backed L2 SAST rules for JavaScript, TypeScript, and Python injection, XSS, unsafe deserialization, redirects, and information leakage, plus high-confidence Java direct-request checks for JDBC, process execution, and ObjectInputStream deserialization
- Optional L3 semantic checks with DeepSeek, Claude, OpenAI-compatible, local Ollama, or VibeGuard Pro providers, plus local heuristic fallback
- Local package verification cache with offline seed mode and optional remote checks for npm, PyPI, Cargo, Go modules, and Maven
- Local SQLite scan history in `~/.vibeguard/findings.db`
- CLI scanner for local and CI usage
- Shared `~/.vibeguard/config.json` defaults for CLI and VSCode scans

## Development

```bash
nvm use
npm install
npm run build
npm test
```

Development, CI, and the Docker image use Node.js 22 LTS. Node.js 24.14.1 has an intermittent V8 shutdown failure when this project's Tree-sitter WASM and experimental SQLite tests run together; use Node 22 for test and release work until that runtime regression is resolved.

To try the extension in VSCode, open this folder in VSCode and run the extension host from the debugger after building.

## JetBrains Plugin

The JetBrains module reuses `vibeguard-lsp --stdio`, so its diagnostics and mechanical quick fixes match the CLI and
VSCode extension. It targets JetBrains commercial IDEs with the LSP API, starting from the 2025.2 platform release.

```bash
cd jetbrains
./gradlew buildPlugin
```

The distribution ZIP is written to `jetbrains/build/distributions/`. Node.js 18 or later is required at runtime; use
`VIBEGUARD_NODE_PATH` or `VIBEGUARD_LSP_PATH` to override the Node executable or LSP script in managed environments.
See [jetbrains/README.md](jetbrains/README.md) for supported file types and Windows instructions.

Watch the [14-second CLI demo](media/vibeguard-demo.mp4) for a real scan of the deliberately unsafe [demo sample](demo/unsafe-ai-sample.ts).

## Marketplace Release

The `Marketplace Release` workflow packages both editor extensions on every manual dispatch and uploads the VSIX and
JetBrains ZIP as workflow artifacts. Pushing an exact version tag such as `v0.1.0` additionally publishes those packages
after checking that `package.json` and `jetbrains/build.gradle.kts` use the same version. Configure `VSCE_PAT` and
`JETBRAINS_MARKETPLACE_TOKEN` as GitHub repository secrets; neither token is stored in the repository or used by normal CI.
Use the Gradle property `-PjetbrainsChannel=eap` to publish a non-default JetBrains Marketplace channel when running the
publish task outside the workflow.

## Docker

The Docker image packages the CLI, LSP bundle, and Tree-sitter WASM grammars for a reproducible CI or private deployment
runtime. Git is included so `ai-code-scan` can inspect repository history.

```bash
docker build -t vibeguard:local .
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --fail-on high
docker run --rm -v "$PWD:/workspace" vibeguard:local scan /workspace --mode ai-code-scan --ai-detection aggressive
```

## Team Dashboard

`findings serve` turns the stored findings history into a deployable team dashboard with developer risk, rule, severity,
dismissal, trend, and opt-in anonymous feedback-signal views. It listens on `127.0.0.1:8787` by default. Use `--host 0.0.0.0` only behind a private network
or reverse proxy.

For a small private deployment, an environment-backed service token remains available as an emergency administrator
credential. Do not put that token in a CI log or source file, and do not leave it in a bookmarked or shared URL.

```bash
VIBEGUARD_DASHBOARD_TOKEN=replace-with-a-long-random-value \
  node dist/cli.js findings serve --db ~/.vibeguard/findings.db --token-env VIBEGUARD_DASHBOARD_TOKEN
```

For enterprise deployments, use a standards-based OpenID Connect provider. VibeGuard uses authorization code flow with
PKCE, validates signed ID tokens against the provider JWKS, and stores only a short-lived signed HttpOnly dashboard
session. Register `<public-url>/auth/callback` as the provider callback URL. `--public-url` must be a bare HTTPS origin;
HTTP is accepted only for localhost development.

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

OIDC supports a dotted role claim path, such as `realm_access.roles`. An unmapped identity receives `none` access by
default; add `--oidc-default-role viewer` only when every signed-in identity should see dashboard summaries. `viewer`
can use `/` and `/api/summary`, `analyst` can additionally use `/api/findings` and `/api/compliance`, and `admin` can include dismissed results
with `/api/findings?all=true` and inspect `/api/audit`. `/api/session` exposes the current identity and effective role. `/healthz` intentionally
remains unauthenticated for container orchestration.

The service-token flow grants `admin` access. A browser can authenticate it through a reverse proxy, or a one-time
`/?token=<service-token>` visit sets an HttpOnly, SameSite=Strict token cookie for that dashboard origin; it is also
marked `Secure` whenever the public origin uses HTTPS, then redirects to the same URL without the token. Prefer OIDC for
normal users.

For a Docker deployment, mount the directory that holds `findings.db` and publish the dashboard port:

```bash
docker run --rm -p 8787:8787 -e VIBEGUARD_DASHBOARD_TOKEN \
  -v "$PWD/.vibeguard:/data" vibeguard:local \
  findings serve --db /data/findings.db --host 0.0.0.0 --token-env VIBEGUARD_DASHBOARD_TOKEN
```

### Private Deployment Compose

`deploy/compose.yaml` packages the private dashboard as a long-running Compose service with a persistent SQLite volume,
health check, disabled privilege escalation, dropped Linux capabilities, and a default `127.0.0.1` host binding. Its
required environment-variable names and non-secret defaults are documented in `deploy/.env.example`.

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
docker compose --env-file deploy/.env -f deploy/compose.yaml logs -f dashboard
```

To use the enterprise OIDC flow, place the dashboard behind an HTTPS reverse proxy and merge the OIDC override. It enables
secure cookies and requires a bare HTTPS public origin, issuer, confidential client credentials, session secret, and analyst/
administrator role mappings from the same environment file.

```bash
docker compose --env-file deploy/.env \
  -f deploy/compose.yaml -f deploy/compose.oidc.yaml up -d --build
```

The service-token and CI ingest-token values remain separate in both configurations. Keep the default loopback bind unless
a private reverse proxy or network policy is in front of the service.

The Compose service keeps anonymous false-positive collection disabled by default. To enable the existing privacy-minimized
`POST /api/telemetry/false-positive` collector, set `VIBEGUARD_TELEMETRY_COLLECTION=true` and, if needed,
`VIBEGUARD_TELEMETRY_MAX_EVENTS_PER_MINUTE=60` in `deploy/.env`. The container entrypoint adds the corresponding CLI flags
only for `findings serve`; normal scanner containers are unaffected. Keep this endpoint behind TLS when it is reachable
beyond localhost, and use it only with explicitly opted-in clients.

### Central CI Ingestion

Private dashboards can receive scan history from CI without sharing the dashboard administrator token. Enable a separate
ingest token on the dashboard, keep the dashboard behind TLS in production, and give only that ingest token to CI. The
`POST /api/ingest` endpoint accepts only JSON scan payloads with bounded fields, a 5 MiB body limit, and up to 10,000
findings per upload by default. It does not accept dashboard cookies or OIDC sessions, and successful uploads are recorded
as `findings.ingested` audit events without credentials.

Every upload may carry a stable project identifier. Use `--findings-project` from a generic CLI environment; the GitHub
Action defaults it to `GITHUB_REPOSITORY` and exposes `findings_project` only for overrides. The team dashboard renders a
project-risk table whose assigned project names link to the matching filtered view. Use `--project <id>` with CLI history commands or `findings serve` to pin a view, or add
`?project=<id>` to authenticated dashboard summary, findings, compliance, or HTML requests when the server is not pinned.

For team-level CI governance, an administrator can issue one project-scoped ingest credential through the protected
`/api/projects` endpoint. The raw token is returned only when it is created or rotated; SQLite stores only its SHA-256
digest. A project token can upload only when `scan.project` exactly matches its assigned project, and revocation immediately
rejects further uploads. The legacy global ingest token remains available as a break-glass or migration credential.
Administrators can manage the same credential lifecycle from the `Project integrations` link in the protected dashboard;
the page displays each newly created or rotated token only once, provides a copy action without browser storage, and renders
a copyable GitHub Action fragment that references the dedicated CI secret without embedding the raw token. The same page
also manages per-project custom-rule YAML. Rules are parsed before saving, limited to 100 rules and 256 KiB per project,
and can be downloaded only by a dashboard administrator, the break-glass ingest credential, or the matching project
credential. CI receives the rules through the separate `GET /api/project-rules/download?project=<id>` endpoint; a missing
project rule set is treated as intentionally unconfigured unless the workflow marks it required.

```bash
# Create: returns { project, token, createdAt, updatedAt, created } once.
curl --fail-with-body -X POST https://guard.example.com/api/projects \
  -H "Authorization: Bearer $VIBEGUARD_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"project":"acme/payments-api"}'

# Rotate an existing credential, or revoke it.
curl --fail-with-body -X POST https://guard.example.com/api/projects \
  -H "Authorization: Bearer $VIBEGUARD_DASHBOARD_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"project":"acme/payments-api","rotate":true}'
curl --fail-with-body -X DELETE 'https://guard.example.com/api/projects?project=acme%2Fpayments-api' \
  -H "Authorization: Bearer $VIBEGUARD_DASHBOARD_TOKEN"
```

```bash
export VIBEGUARD_DASHBOARD_TOKEN=replace-with-break-glass-token
export VIBEGUARD_FINDINGS_INGEST_TOKEN=replace-with-dedicated-ci-token

node dist/cli.js findings serve --db ~/.vibeguard/findings.db --host 0.0.0.0 \
  --token-env VIBEGUARD_DASHBOARD_TOKEN \
  --ingest-token-env VIBEGUARD_FINDINGS_INGEST_TOKEN
```

The CLI can then upload one completed scan. Upload failures remain warnings by default so an unavailable dashboard does
not hide scanner results; add `--findings-upload-required` when the centralized record is a required CI gate.

```bash
VIBEGUARD_FINDINGS_INGEST_TOKEN=replace-with-dedicated-ci-token \
  node dist/cli.js scan . --no-store-findings \
  --findings-endpoint https://guard.example.com/api/ingest \
  --findings-token-env VIBEGUARD_FINDINGS_INGEST_TOKEN \
  --findings-project acme/payments-api \
  --findings-upload-required
```

## Pro Subscription

The `vibeguard` L3 provider uses the official hosted service and its server-enforced Pro, Team, or Enterprise allowance.
It does not replace the free BYOK paths: DeepSeek, Claude, OpenAI-compatible endpoints, and local Ollama remain available
without a VibeGuard subscription. Store the Pro credential in `VIBEGUARD_PRO_API_KEY` for CI and Docker, use
`vibeguard llm-key set --provider vibeguard --from-env VIBEGUARD_PRO_API_KEY` for CLI and shared LSP, or use
`VibeGuard: Set LLM API Key` with provider `vibeguard` in VSCode so it is held in SecretStorage.

```bash
export VIBEGUARD_PRO_API_KEY=replace-with-pro-credential
node dist/cli.js llm-key set --provider vibeguard --from-env VIBEGUARD_PRO_API_KEY
node dist/cli.js scan src --l3 --llm-provider vibeguard
node dist/cli.js subscription status
```

The default service origin is `https://api.vibeguard.dev/v1`. Private service deployments can set
`VIBEGUARD_PRO_API_BASE_URL`; it must use HTTPS except for localhost development. The VSCode extension and LSP deliberately
ignore a workspace-level `llmBaseUrl` for the hosted provider, so a repository cannot redirect a stored Pro credential.

The hosted contract is OpenAI-compatible for `POST /chat/completions` and exposes `GET /account/usage` for the status
command. The usage response contains `plan`, `status`, optional `features`, and `usage.l3_requests` with `used`, `limit`,
and optional `reset_at`. Billing, credit checks, and request limits remain server-side; the client never writes the Pro
credential into `config.json`.

## CLI

```bash
npm run build
node dist/cli.js scan path/to/project --package-verification seed --fail-on high
node dist/cli.js scan src --json
DEEPSEEK_API_KEY=... node dist/cli.js scan src --l3 --llm-provider deepseek
VIBEGUARD_PRO_API_KEY=... node dist/cli.js scan src --l3 --llm-provider vibeguard
VIBEGUARD_PRO_API_KEY=... node dist/cli.js subscription status
node dist/cli.js scan src --l3 --llm-provider local --llm-model llama3.2
node dist/cli.js scan . --sarif vibeguard.sarif --github-annotations
node dist/cli.js scan . --markdown vibeguard-report.md
node dist/cli.js scan . --format markdown
node dist/cli.js scan . --ignore-rules ~/.vibeguard/ignore-rules.yml
node dist/cli.js scan src --package-index ~/.vibeguard/package-index.json.gz
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
node dist/cli.js findings compliance --framework all --days 90 --output vibeguard-compliance-report.md
node dist/cli.js findings audit --limit 100
node dist/cli.js rules export-semgrep --output vibeguard-semgrep.yml
```

`--l3` enables semantic endpoint checks. When a configured provider has credentials, VibeGuard calls the LLM with detected framework, function, and route context and expects structured JSON findings; before source is sent to a remote provider, high-confidence secret literals are replaced with a placeholder, including complete private-key blocks, and only the source filename is included rather than its directory path. Local Ollama analysis keeps the source local and does not apply this transport redaction. Without credentials, VibeGuard falls back to conservative local heuristics for missing authentication, rate limiting, input validation, parameterized database queries, IO error handling, and output encoding around Express, FastAPI/Flask, Django, and Spring MVC route handlers. Django support resolves same-file `urlpatterns` `path`/`re_path` entries and standalone `views.py` function views that return Django/DRF responses, while recognizing common auth, rate-limit, HTTP-method, and form-validation decorators. Spring context includes class-level `@RequestMapping` prefixes and method-level mappings, while recognized `@PreAuthorize`, `@RateLimiter`, `@Valid`, and `try`/`catch` controls suppress the corresponding missing-control finding. An LLM may optionally return a replacement for the exact evidence snippet; VibeGuard validates its range, rejects fenced/diff-like output, and exposes it as a non-preferred Quick Fix for review. CLI and LSP resolve environment variables such as `DEEPSEEK_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `VIBEGUARD_LLM_API_KEY`, and `VIBEGUARD_PRO_API_KEY` first, then use the native credential store configured by `vibeguard llm-key`; the CLI intentionally has no plaintext API-key flag. Rust `use` declarations match Cargo package names with either hyphens or underscores, so `use actix_web::...` is resolved against the `actix-web` package during cold-start seed checks as well as in the local index.

When L3 recognizes Express, Python, or Spring route handlers, it sends bounded handler blocks with their original file line numbers instead of blindly truncating the file prefix. The prompt asks the model to trace request-derived values through aliases and helper calls to security-sensitive sinks, and treats comments, strings, and all source text as untrusted data rather than instructions.

For Express and Router files, local L3 also recognizes same-file `app.use`/`router.use` authentication and rate-limit middleware. Controls registered for a path prefix apply only to matching routes, and the detected control scopes are included with remote L3 route reviews.

Provider controls:

```bash
node dist/cli.js scan src --l3 --llm-provider deepseek --llm-model deepseek-v4-flash
node dist/cli.js scan src --l3 --llm-provider claude --llm-api-key-env ANTHROPIC_API_KEY
node dist/cli.js scan src --l3 --llm-provider openai --llm-base-url https://api.openai.com/v1
node dist/cli.js scan src --l3 --llm-provider local --llm-base-url http://localhost:11434
VIBEGUARD_PRO_API_KEY=... node dist/cli.js scan src --l3 --llm-provider vibeguard
node dist/cli.js llm-key set --provider deepseek --from-env DEEPSEEK_API_KEY
node dist/cli.js llm-key status --provider deepseek
```

Remote LLM base URLs must use HTTPS. HTTP is accepted only for `localhost`, `127.0.0.1`, or IPv6 loopback development endpoints; redirects, URL credentials, query parameters, and fragments are rejected before source or API credentials are sent.

The L1 secret scanner combines provider-specific signatures for keys and tokens, sensitive assignment context such as `apiKey`, `clientSecret`, `Authorization`, and `webhookSecret`, Shannon-entropy scoring for random-looking literals, and false-positive filters for placeholders, hashes, fixtures, UUIDs, and normal encoded data. High-confidence JavaScript/TypeScript and Python secret assignments include quick fixes that replace committed literals with environment-variable reads. The AI pattern library covers common generated-code mistakes such as placeholder credentials, unsafe JWT handling, wildcard CORS with credentials, disabled TLS verification, weak password hashing, plaintext password comparison, insecure random token generation, placeholder framework secrets, and public object-storage ACLs. L2 covers high-confidence SQL injection, XSS, SSRF, path traversal, unsafe deserialization, command injection, open redirect, and error-detail leakage patterns; SSRF covers request-controlled URL targets across Fetch, Axios, Node HTTP(S), Requests, HTTPX, Java `RestTemplate`, `WebClient`, JDK `HttpRequest`, and OkHttp `Request.Builder`, command injection includes Node `exec`/`execSync`, shell-enabled `spawn`/`spawnSync`/`execFile` calls, and Python execution APIs when command values are user-controlled, while path traversal includes Node `fs` and `fs.promises` reads, writes, appends, streams, and deletes plus Java `Files`, `Paths`, and `File` operations whose paths are direct servlet request input. Java open-redirect checks cover request-controlled Servlet, `RedirectView`, and `redirect:` targets; Java error-detail checks cover 5xx Servlet or Spring responses that return an exception message. High-confidence `innerHTML` and unsafe `yaml.load()` findings include mechanical quick fixes.

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

Set `telemetry` to `true` only when you want to contribute anonymous false-positive feedback. VibeGuard sends an event only after a user selects the standard `False positive` dismissal reason. The event includes a truncated SHA-256 rule fingerprint, finding type/layer/severity, and ignore scope; it never includes source code, evidence, package names, file paths, line numbers, project identifiers, authors, finding IDs, or free-form reasons. Delivery failures do not block scans or ignore actions. The default destination is the VibeGuard HTTPS telemetry endpoint; `VIBEGUARD_TELEMETRY_ENDPOINT` can override it for approved localhost development or a private HTTPS collector.

A self-hosted dashboard can act as that collector only when started with `--telemetry-collection`; it is disabled by default. The public `POST /api/telemetry/false-positive` endpoint accepts only the event schema above, rejects extra fields, limits bodies to 2 KiB, and rate-limits each direct network source to 60 events per minute by default. It stores daily aggregates only, then shows aggregate counts by rule fingerprint in the authenticated dashboard. When the dashboard's own scan history has exactly one matching rule, it displays that local rule ID without changing what clients send. Point opted-in clients at the endpoint with `VIBEGUARD_TELEMETRY_ENDPOINT=https://guard.example.com/api/telemetry/false-positive`; keep the collector behind TLS, or use localhost for development.

`dedup_with_existing_tools` dismisses duplicate L2 findings when nearby SonarQube, Snyk, Semgrep, or CodeQL annotations already cover the same issue. Override it in the CLI with `--dedup-existing-tools` or `--no-dedup-existing-tools`.

Use `ignored_findings` for exact finding-id dismissals. The CLI can maintain this list without hand-editing JSON:

```bash
node dist/cli.js config ignore-finding vg_12345678
node dist/cli.js config unignore-finding vg_12345678
```

`llm_api_key` must remain `null`; VibeGuard rejects plaintext keys in config JSON. VSCode stores provider keys in SecretStorage via `VibeGuard: Set LLM API Key`. For CLI and shared-LSP use, `vibeguard llm-key set --provider <provider> --from-env <ENV_VAR>` stores the credential in Windows DPAPI (bound to the current user), macOS Keychain, or Linux Secret Service; `--stdin` accepts an interactive or piped value without a plaintext argument. If that native service is unavailable, set `VIBEGUARD_LLM_CREDENTIAL_PIN` (at least eight characters) or pass `--pin-env <ENV_VAR>` during setup: VibeGuard derives a key from the PIN and local machine identifier with scrypt, then stores each credential using AES-256-GCM. The PIN must be present in `VIBEGUARD_LLM_CREDENTIAL_PIN` when the CLI or shared LSP reads this fallback. `llm-key delete` removes either storage form and `llm-key status` reports only whether one exists. Environment variables continue to take precedence, which keeps CI and one-off scans non-interactive.

## Findings Storage

CLI and VSCode scans persist scan runs and findings to `~/.vibeguard/findings.db` by default. Stored dismissed findings remain queryable for audit trails, while normal diagnostics and fail thresholds still use only active findings. The database has a 100 MB on-disk budget that includes SQLite WAL sidecar files. When that budget is exceeded, VibeGuard compacts the database and removes the oldest scan history first, then the oldest audit and anonymous-feedback history only when necessary. `findings status` and `findings summary` show the current footprint and budget; `findings prune` remains available when an operator needs a specific retention period.

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

`findings summary` aggregates stored history by severity, type, top detection rules, dismissal reason, git author, daily trend, and the active-finding delta between the latest two scans. It also records per-rule false-positive counts and rates only when dismissals use the standard `False positive` reason; a dedicated list sorts these rules by rate so teams can prioritize rule-quality work. The delta separates introduced, resolved, and persistent risks, scoped to the selected project and reporting window. CLI and VSCode scans record the latest git author for files with findings when git history is available, so the summary and dashboard can surface developer risk hotspots. `findings dashboard` writes a standalone HTML dashboard with the same trend, author, dismissal-reason, scan-delta, and rule-feedback data, suitable for CI artifacts, team reports, false-positive review, or offline review. VSCode users can run `VibeGuard: Export Findings Dashboard` to generate and open the same dashboard from the command palette.

`findings compliance` writes a source-free Markdown evidence report for `soc2`, `iso27001`, or both. It maps scan
history to selected control objectives, open mapped findings, trend cadence, top rules, and dismissal reasons. The report
also includes aggregate dashboard action and access-denial counts without subjects or request metadata. It is technical
evidence for an audit workflow; it is explicitly not a certification, attestation, or proof of compliance.
Use `--json` to emit the same evidence shape for a GRC system, and `/api/compliance` from the protected team dashboard
for an analyst-role JSON view.

The private dashboard records successful OIDC sign-ins/sign-outs, sensitive findings and compliance views, audit-log
views, and authenticated authorization denials in the same SQLite database. Audit metadata is bounded and filters keys
such as tokens, cookies, authorization headers, passwords, and provider codes. `findings audit` is the local operator
view; `/api/audit` requires the dashboard `admin` role. `findings prune` applies the selected retention cutoff to both
scan history and audit events.

GitHub Action scans default to `store_findings: false` so CI jobs do not write local history unless explicitly requested.

## Package Index

The scanner can use a local package-name index before falling back to the seed catalog or remote registry checks. Partial indexes act as an existence cache; full indexes can also prove that a package is missing and suggest close package names for typos or slopsquatting-like hallucinations. VSCode and the shared LSP default to non-blocking remote verification: edit-time L1 first uses the local seed/index, then verifies unresolved package names asynchronously. CLI and Action defaults remain `seed` for deterministic offline scans. Python scanning recognizes imports, dependency manifests, executable `pip install` automation calls, notebook-style `!pip install` commands, shell and PowerShell scripts, Dockerfiles, and YAML CI commands. Java and Kotlin dependency parsing supports Maven POM files, Gradle build scripts, Gradle `*.versions.toml` catalogs with `module`, `group`/`name`, or direct coordinates, plus exact external class imports. Java SE namespaces, Kotlin runtime, and Android namespaces are excluded from Maven class lookup; external `javax` packages such as Servlet, JPA, and JAXB remain eligible. Kotlin aliases are resolved to their original class, while wildcard imports and lower-case top-level function imports are intentionally skipped to avoid false positives. Seed and remote verification support npm, PyPI, Cargo, Go modules, and Maven coordinates; remote Maven lookup also verifies exact Java and Kotlin import classes through its class index, while Maven Central responses are checked for a matching result rather than HTTP success alone. Local package-name sync can populate indexes for all five registries.

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

Configured refreshes persist registry ETag and Last-Modified metadata with the local index. Once an index is due, VibeGuard sends conditional requests only to the same registry URL; a `304 Not Modified` response refreshes the local timestamp without downloading or re-importing the package list. For npm `_all_docs` sources, both `packages sync npm` and the first configured full sync store a conservative replication sequence. Later stale refreshes consume same-source `_changes` batches, applying package additions and removals without downloading the complete index. Manual forced refreshes, changed registry URLs, and mirrors that do not expose a compatible change stream automatically use the full-refresh path.

When a package is absent from a full local index, VibeGuard combines curated seed suggestions with fuzzy matches from the synced index. The first close match is exposed as an editor/CLI fix when the import specifier can be safely replaced.

`packages sync-config` reads `package_cache.languages`, `package_cache.update_interval`, and `package_cache.lightweight_mode` from config.json. It skips fresh registries, refreshes stale registries, and upgrades partial indexes when lightweight mode is disabled. Use `--force` to refresh everything now, `--limit` to override the lightweight target, and `--url registry=URL` for a registry mirror or test fixture.

The VSCode extension also starts a background package-cache sync on startup. On first run it shows a one-time cold-start note that secret, config, and AI-pattern checks are active immediately while the package-name cache prepares hallucinated-package detection. With lightweight mode enabled, it first builds the quick partial index and immediately rechecks open documents, then continues with the full index in Tier 2. Set `package_cache.background_full_sync` or `vibeguard.packageCacheBackgroundFullSync` to `false` to retain only the quick index. It prioritizes package managers detected in the current workspace, then queues the other configured registries in the same background sync. The status bar identifies the current tier, registry, and completion percentage; other L1/L2/L3 checks remain active if a cache refresh fails. Run `VibeGuard: Sync Package Cache` from the command palette to force a refresh of the configured tier.

In VSCode, normal edit-time scans run L1 immediately for fast feedback, then debounce L2 SAST for 500ms by default. Package verification defaults to `remote`: edit-time scans first use local seed/cache results and schedule the remote registry check independently after a 600ms delay from the latest automatic scan, so registry latency does not block diagnostics; the current document version must still match before any asynchronous result is shown. Set `vibeguard.packageVerification` to `seed` for offline-only editor checks. When L3 is enabled, semantic analysis is debounced for 2 seconds after edits by default; saves and manual scans run all enabled layers immediately. Adjust the analysis delays with `vibeguard.l2DebounceMs` and `vibeguard.l3DebounceMs`. The status bar tooltip includes recent scan timing totals and shows a watch marker when a file exceeds the L1/L2/L3 performance budget.

Storage modes:

- `auto`: use SQLite when the current Node runtime supports `node:sqlite`, otherwise JSON
- `sqlite`: store package resolution cache and package index in `~/.vibeguard/packages.db`
- `json`: store verification results in `~/.vibeguard/package-cache.json` and package names in gzip-compressed `~/.vibeguard/package-index.json.gz`; legacy `package-index.json` files are read automatically and migrate on the next index write

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

Package verification modes:

- `seed`: instant, offline checks against the built-in known-good/known-hallucinated catalog
- `remote`: seed + cached remote npm, PyPI, Cargo, Go module, and Maven Central verification with a 3 second timeout and at most five in-flight registry requests; exact Java class imports use Maven Central's class index rather than the coordinate cache. Repeated references to the same package share one in-flight lookup. Only definitive misses are cached; an unavailable, rate-limited, or malformed registry response produces a non-blocking warning and is retried on a later scan after connectivity recovers
- `off`: disables package existence checks

For pull request feedback, the Action can emit GitHub workflow annotations with `github_annotations: true`, append a Markdown report to the job summary with `step_summary: true`, and optionally create/update a sticky PR comment with `pr_comment: true`. Set `pr_review_comments: true` to create a single `COMMENT` review containing up to `pr_review_comment_limit` active findings on changed diff lines. It defaults to `false`, requires `pull-requests: write`, skips existing VibeGuard comments at the same path/line/rule, and never includes a finding's code evidence. Set `sarif` to write a SARIF 2.1.0 report that can be uploaded with `github/codeql-action/upload-sarif`; set `markdown` to keep the Markdown report as an artifact path. Set `findings_endpoint` to the private dashboard's `/api/ingest` endpoint and provide its dedicated token only through the environment variable named by `findings_token_env`; `findings_upload_required` is opt-in. Set `store_findings: true` with `dashboard: true` or `compliance: true` to generate the corresponding HTML dashboard or source-free compliance evidence artifact.

The composite Action sets up Node.js 22 before installing and building VibeGuard, so callers do not need to select a Node version separately.

Set `findings_rules_endpoint` to the private dashboard's project-rule download endpoint to append centrally managed YAML
rules to the scan. The Action uses the same environment-backed project credential, accepts only HTTPS endpoints except
loopback HTTP development, does not follow redirects, and never writes the token to output. A `404` means that no central
rule set is configured for the project and leaves local `custom_rules` active; other download failures warn by default or
fail the job with `findings_rules_required: true`.

Set `mode: ai-code-scan` to analyze changed files but report only findings that overlap changed lines attributed to AI. VibeGuard parses zero-context diff hunks, uses `git blame` on the checked-out head for line attribution, and reads the blamed commit message only when `ai_detection: message` or `aggressive` needs it. `author` matches the blamed author, `message` matches the blamed commit body or trailers, and `aggressive` includes either signal plus additions of 50 or more lines. When git history or blame cannot be inspected, VibeGuard falls back to a full scan so CI does not silently miss findings.

## Semgrep Export

VibeGuard can export its core AI/security rules to a Semgrep config file. Built-in AI pattern rules are exported from the same rule definitions used by the scanner. Core loose-configuration coverage includes debug mode, wildcard hosts and CORS, disabled host/CSRF/Spring Security controls, wildcard Spring origins, and Python dynamic execution or pickle deserialization. Provider-specific secret signatures are exported directly; contextual high-entropy secret detection is exported as a conservative regex approximation because the full Shannon-entropy and false-positive filtering logic runs inside the VibeGuard scanner.

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

Use `--custom-rules ./vibeguard-rules.yml` in the CLI, `custom_rules` in `config.json`, `custom_rules` in the Action, or `vibeguard.customRules` in VSCode. Private-dashboard administrators can additionally save a validated project ruleset through `Project integrations` and give CI its `findings_rules_endpoint`; Action scans merge that downloaded ruleset with local custom rules. Custom findings use rule ids like `custom.company_public_s3_acl`, so they can be ignored with the normal ignore-rules.yml flow.

## LSP Server

```bash
npm run build
node dist/lspServer.js --stdio
```

The LSP server publishes VibeGuard diagnostics with the same scanner used by the VSCode extension and CLI. On edits it publishes L1 immediately, debounces L2 by 500ms and L3 by 2s, and runs all enabled layers immediately when a document is saved; `l2DebounceMs` and `l3DebounceMs` can override those values through LSP configuration. Its default `remote` package mode first publishes local L1 findings, then checks unresolved packages after the edit-time delay. Newly detected critical findings also use the standard LSP warning dialog, offering safe mechanical fixes plus line, file, global-rule, and package-name ignores; clients that advertise `window.showDocument.support` also receive a `Manage Ignore Rules` action that creates and opens the shared YAML file. Set `showCriticalPopups: false` in LSP settings to disable those alerts. The server exposes LSP `quickfix` code actions for the same operations, so non-VSCode LSP clients can apply package-name, secret-assignment, config, SAST, and false-positive workflows without leaving the editor. Mechanical quick fixes resolve the current finding on the server and verify its evidence before requesting the edit. L3 generated replacements additionally ask for confirmation and recheck the current document before the workspace edit.

On initialization, the LSP also refreshes the shared package-name cache in the background, so JetBrains and other LSP clients receive the same cold-start behavior as VSCode. It reads `package_cache` from the shared config, prioritizes registries identified by dependency manifests at workspace roots, and rechecks open documents' L1 package findings when each tier is updated. With lightweight mode enabled, it prepares a quick partial index before continuing to the full index in Tier 2; `background_full_sync` can disable the upgrade. Clients that advertise standard LSP `window.workDoneProgress` receive native tier and percentage updates; other clients keep the console progress log without extra protocol traffic. LSP initialization options or `workspace/didChangeConfiguration` settings under `vibeguard` can override `showCriticalPopups`, `autoSyncPackageCache`, `configPath`, `packageCacheLanguages`, `packageCacheUpdateInterval`, `packageCacheLightweightMode`, and `packageCacheBackgroundFullSync`.

## VSCode Settings

- `vibeguard.enabled`
- `vibeguard.scanOnChange`
- `vibeguard.scanOnSave`
- `vibeguard.configPath`
- `vibeguard.packageVerification`: `remote` (default), `seed`, or `off`
- `vibeguard.autoSyncPackageCache`
- `vibeguard.packageCacheLanguages`
- `vibeguard.packageCacheUpdateInterval`
- `vibeguard.packageCacheLightweightMode`
- `vibeguard.packageCacheBackgroundFullSync`
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
- `VibeGuard: Show Pro Subscription Status`
- `VibeGuard: Review and Apply All Pro Fixes in Current File`

Dashboard command:

- `VibeGuard: Export Findings Dashboard`

## VSCode Quick Fixes

VibeGuard publishes diagnostics with quick actions. When a finding has a safe mechanical fix, the editor lightbulb, the VSCode Findings sidebar context menu, or an LSP client quickfix can apply it directly. Before VSCode applies a single fix, it verifies the original finding evidence still matches the open document; redacted secret findings are revalidated by regenerating their safe fix from current source without exposing the secret. Hallucinated packages now expose every verified, safe similar-name candidate as an individual Quick Fix, with the best match marked preferred; critical package alerts in VSCode and shared LSP clients explain the Slopsquatting risk and offer every candidate when more than one is available. Current fixes also cover hardcoded secret assignments to environment-variable reads, debug/CORS/host-check toggles, `yaml.load()` to `yaml.safe_load()`, explicitly SQLite-backed single-expression SQL f-strings to parameterized `execute()` calls, and high-confidence `innerHTML` to `textContent` cases. Critical VSCode alerts include a local `Learn More` action that opens the finding location and appends its rule, evidence, suggestion, and available fix to the VibeGuard output channel. `VibeGuard: Apply All Safe Fixes in Current File` applies non-overlapping L1/L2 mechanical fixes in one reviewed operation. With the VibeGuard Pro provider and credential selected, `VibeGuard: Review and Apply All Pro Fixes in Current File` combines those mechanical fixes with a multi-select review of non-overlapping L3 replacements; each L3 edit must still match the current document evidence before the final confirmation. The VSCode extension also exposes ignore actions for the current finding, the current file, the global rule, or a hallucinated package name.

## Scope Notes

The Rust LSP migration has started with a standalone `tower-lsp` native L1 server in [`rust-lsp/`](rust-lsp/). It keeps open documents in memory and publishes diagnostics for bundled NPM hallucination seeds, hardcoded OpenAI keys, and the current unsafe-configuration rules. Its ranges use LSP UTF-16 columns and secret diagnostic messages never include a matched key. Run it over stdio with `cargo run --manifest-path rust-lsp/Cargo.toml -- --stdio`.

The Node LSP remains the VSCode default while the Rust service reaches parity with package-index synchronization, all registry parsers, code actions, L2/L3 scheduling, ignore rules, and persisted findings. Both use the same rule IDs where native coverage exists, so the editor integration can move over without changing the user-facing finding contract.

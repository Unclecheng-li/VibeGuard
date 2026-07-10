# Changelog

## 0.1.0

- Initial VibeGuard MVP extension package.
- Real-time L1 findings for hallucinated npm, PyPI, Cargo, Go module, and Maven packages, hardcoded secrets, loose configuration, and common AI coding mistakes.
- Lightweight L2 SAST diagnostics for common injection and unsafe deserialization patterns.
- Optional local L3 semantic endpoint checks for missing authentication, rate limiting, validation, and output encoding.
- Findings view, critical popups, quick fixes, ignore rules, CLI scanner, LSP server, GitHub Action, and package index sync/cache support.
- CI reporting with JSON, SARIF, and GitHub workflow annotations for PR feedback.
- Git-aware `ai-code-scan` mode for filtering PR scans to changed files touched by AI-looking authors, commit messages, or large generated diffs.
- Semgrep YAML export for core VibeGuard AI/security rules.
- Custom YAML rules for team-specific VibeGuard findings across CLI, VSCode, LSP, and GitHub Action.
- Shared `~/.vibeguard/config.json` support with CLI `config init`, `--config`, `--no-config`, VSCode `vibeguard.configPath`, and GitHub Action `config` inputs.
- Existing-tool deduplication for L2 findings with nearby SonarQube, Snyk, Semgrep, or CodeQL annotations, configurable across CLI, VSCode, LSP, GitHub Action, and config.json.
- L2 SAST coverage for open redirects and server error-detail information leakage, including Semgrep export metadata.
- Local SQLite findings history in `~/.vibeguard/findings.db`, with CLI `findings status/list/prune`, VSCode persistence, and opt-out flags for local/CI scans.
- Exact finding-id dismissal through config `ignored_findings`, VSCode `vibeguard.ignoredFindings`, LSP settings, and CLI `config ignore-finding` / `config unignore-finding`.
- Mechanical quick fixes for high-confidence L2 `innerHTML` and unsafe `yaml.load()` findings, plus L1 YAML loader findings.
- Package-name remote sync expanded beyond npm/PyPI to Cargo crates, Go module index, and Maven Central search for richer local indexes.
- Config-driven package index refresh via `vibeguard packages sync-config`, honoring `package_cache.languages`, `update_interval`, and `lightweight_mode`.
- VSCode startup background package-cache sync with workspace package-manager detection, status-bar progress, output logging, and a manual `VibeGuard: Sync Package Cache` command.
- L3 semantic analysis can now use DeepSeek/OpenAI-compatible, Claude, or local Ollama providers, with CLI/LSP environment-variable credentials, VSCode SecretStorage commands, structured JSON finding parsing, and local fallback.
- Expanded the L1 AI-pattern rule library from 6 to 21 high-confidence generated-code mistakes, including JWT, CORS, TLS, password hashing, token randomness, framework secret, and object-storage ACL issues, with automatic Semgrep export coverage.
- PR-friendly Markdown scan reports via CLI `--format markdown` / `--markdown`, plus GitHub Action job-summary output and optional sticky PR comments.
- Cargo and Maven package-name sync now paginates remote registry/search results for more complete local package indexes while preserving `--limit` lightweight sync behavior.
- Full and partial local package indexes now provide fuzzy package-name suggestions, improving hallucinated-package quick fixes beyond the built-in seed catalog.
- VSCode edit-time scans now run L1/L2 immediately and debounce L3 semantic analysis separately, with `vibeguard.l3DebounceMs` controlling the delay.
- L1 hardcoded-secret detection now combines provider token signatures, contextual high-entropy assignment analysis, bearer-token handling, and filters for common hash/fixture/placeholder false positives, with expanded Semgrep export coverage.
- Scanner results now include L1/L2/L3 timing breakdowns and PRD performance-budget checks, surfaced in CLI JSON/human/Markdown reports, GitHub Action summaries, VSCode status tooltips, and LSP console warnings.
- L1 hardcoded-secret assignments now include mechanical quick fixes for JavaScript/TypeScript `process.env` reads and Python `os.getenv` reads, including an `import os` insertion when needed.
- VSCode edit-time scans now follow the PRD timing model more closely: L1 runs immediately, L2 is debounced with `vibeguard.l2DebounceMs` (500ms default), and L3 keeps its separate debounce while findings from layers that have not rerun are preserved until their refresh completes.

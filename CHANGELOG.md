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

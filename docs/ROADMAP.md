# AgentProof OS Roadmap

## Phase 1 - CLI preflight

- [x] Package skeleton and console command.
- [x] Secret scanner.
- [x] MCP config scanner.
- [x] Agent instruction scanner.
- [x] Dependency/script scanner.
- [x] Repo hygiene checks.
- [x] JSON, Markdown, and SARIF reports.
- [x] Severity gate for CI.
- [x] Unit tests for initial detectors.

## Phase 2 - GitHub Action

- [x] Composite action wrapper.
- [x] CI workflow for the AgentProof repo.
- [ ] Upload SARIF to GitHub code scanning.
- [ ] Pull request summary comments.
- [ ] Rule allowlist and baseline file.

## Phase 3 - MCP deep audit

- [ ] Tool descriptor diffing.
- [ ] OAuth metadata validation.
- [ ] Token passthrough detection.
- [ ] Remote MCP endpoint policy.
- [ ] Filesystem scope minimization suggestions.

## Phase 4 - Agent flight recorder

- [ ] Import Cursor/Codex/Claude session summaries.
- [ ] Map files touched by agent session.
- [ ] Detect risky command patterns from logs.
- [ ] Export audit bundle for review.

## Phase 5 - Local dashboard

- [ ] SQLite scan history.
- [ ] Repo inventory.
- [ ] MCP inventory.
- [ ] Findings triage board.
- [ ] Usage/cost bridge from AI coding usage tracker.

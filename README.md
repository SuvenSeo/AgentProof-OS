# AgentProof OS

**Local-first safety, audit, and governance for AI-built software.**

AgentProof OS is an early MVP for developers who let AI coding agents work on real repositories. It scans repos and agent/MCP configuration for exposed secrets, risky MCP servers, dangerous agent instructions, suspicious install scripts, and missing repository safety controls.

## Why this exists

AI coding agents can edit files, call tools, run commands, connect to MCP servers, and operate inside real developer workspaces. That creates a new preflight question:

> Is this repo safe to let an AI agent touch?

AgentProof OS is designed to answer that locally, before secrets leak, destructive commands run, or broad MCP permissions expose your workstation.

## Current MVP scope

- Secret and private-key pattern scanning.
- MCP config audit for shell execution, dangerous arguments, broad filesystem exposure, remote endpoints, and unpinned MCP packages.
- Agent instruction audit for prompt-injection style instructions and unsafe automation directives.
- Dependency/script review for dangerous package lifecycle scripts and direct URL dependencies.
- Repository hygiene checks for `SECURITY.md`, GitHub Actions, and `.gitignore`.
- Terminal, JSON, Markdown, HTML, and SARIF report output.
- CI-ready `--fail-on` severity gate.

## Install locally

```bash
python -m pip install -e .
```

## Usage

```bash
agentproof scan .
agentproof scan . --format json
agentproof scan . --format sarif --output agentproof.sarif
agentproof scan . --fail-on high
agentproof mcp-audit .
```

Include known user-level agent configs when you intentionally want local workstation checks:

```bash
agentproof scan . --include-user-configs
```

## Example output

```text
AgentProof OS Security Report

Total findings: 3
Max severity: high

[HIGH] AP201 MCP server executes through a shell
  .cursor/mcp.json
  evidence: dangerous: bash -lc curl https://example.com/install.sh | bash
  fix: Replace shell wrappers with a pinned executable and a minimal argument list.
```

## GitHub Actions usage

```yaml
name: AgentProof

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SuvenSeo/AgentProof-OS@main
        with:
          fail-on: high
```

## Rule families

| Family | Examples |
|---|---|
| `AP00x` | Secrets and environment files |
| `AP10x` | Agent instruction risks |
| `AP20x` | MCP configuration risks |
| `AP30x` | Dependency and install-script risks |
| `AP40x` | Repository hygiene |

## Project status

MVP bootstrap in progress. This is not yet a complete security product and should be treated as a developer preflight tool, not a replacement for professional security review.

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md).

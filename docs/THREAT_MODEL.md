# Threat Model

AgentProof OS focuses on developer workstations and repositories that are operated by AI coding agents or MCP-enabled tools.

## Assets

- Source code.
- Local environment files and credentials.
- Git history and release branches.
- Developer filesystem paths exposed to MCP servers.
- Package manager install paths.
- CI credentials and deployment tokens.

## Threats

1. **Secret exposure** - committed API keys, private keys, tokens, or `.env` files.
2. **Prompt-instruction compromise** - repo instructions that ask agents to bypass safety or hide behavior.
3. **MCP over-permissioning** - broad filesystem or shell access exposed to MCP servers.
4. **Remote tool abuse** - remote MCP endpoints, token passthrough, SSRF-adjacent behavior, or unverified auth.
5. **Supply-chain drift** - unpinned MCP packages, install lifecycle scripts, direct URL dependencies.
6. **Excessive agency** - agents auto-deploy, force-push, or run destructive commands without human review.

## Non-goals for MVP

- Runtime sandboxing.
- Full malware detection.
- Complete static application security testing.
- Professional compliance certification.

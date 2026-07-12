from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "__pycache__"}

SECRET_PATTERNS = [
    ("AP001", "high", "Potential OpenAI API key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("AP002", "high", "Potential GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("AP003", "high", "Potential AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AP004", "critical", "Potential private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AP005", "high", "Potential secret-like assignment", re.compile(r"(?i)[A-Z0-9_.-]*(?:api[_-]?key|secret|token|password|private[_-]?key)\s*=\s*['\"]?[^'\"\s#]{12,}")),
]

AGENT_PATTERNS = [
    ("AP100", "high", "Prompt-injection style agent instruction", re.compile(r"(?i)ignore (all )?(previous|prior|system|developer) instructions")),
    ("AP101", "medium", "Instruction encourages bypassing confirmation", re.compile(r"(?i)(never ask|do not ask|don't ask).{0,40}(confirmation|permission|approval)")),
    ("AP102", "high", "Instruction encourages destructive operations", re.compile(r"(?i)(force[- ]?push|rm -rf|delete everything|wipe|drop database)")),
    ("AP103", "high", "Instruction asks agent to hide behavior", re.compile(r"(?i)(do not tell|hide this|silently).{0,50}(user|developer|reviewer)")),
    ("AP104", "medium", "Instruction encourages unrestricted shell usage", re.compile(r"(?i)(run any command|unrestricted shell|no sandbox|full disk access)")),
]

MCP_CONFIGS = [".cursor/mcp.json", ".vscode/mcp.json", "mcp.json", "claude_desktop_config.json", ".claude/mcp.json", ".codex/config.toml"]
SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh"}
DANGEROUS_ARGS = re.compile(r"(?i)(rm\s+-rf|curl\s+.*\|\s*(sh|bash)|wget\s+.*\|\s*(sh|bash)|Invoke-Expression|iex\s|sudo\s|chmod\s+777)")
SENSITIVE_PATH_PARTS = {".ssh", ".aws", ".gnupg", ".kube", "appdata", "library/application support"}
REMOTE_URL = re.compile(r"https?://[^\s'\"]+")
REMOTE_PIPE = re.compile(r"(?i)(curl|wget)\s+[^\n|]+\|\s*(sh|bash|powershell|pwsh)")
DANGEROUS_SCRIPT = re.compile(r"(?i)(rm\s+-rf|chmod\s+777|Invoke-Expression|iex\s|sudo\s)")
UNPINNED_URL_DEP = re.compile(r"(?i)(git\+https?://|https?://).*(\.zip|\.tar\.gz|\.whl|\.egg|github.com)")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    scanner: str
    line: int | None = None
    evidence: str | None = None
    recommendation: str | None = None

    @property
    def sort_key(self) -> tuple[int, str, str, int]:
        return (-SEVERITY_ORDER.get(self.severity, 0), self.path, self.rule_id, self.line or 0)


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > 1_000_000:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="replace")


def scan_secrets(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    ignored = ("example", "placeholder", "replace_me", "changeme", "dummy")
    for path in iter_files(root):
        text = read_text(path)
        if text is None:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if any(marker in line.lower() for marker in ignored):
                continue
            for rule_id, severity, title, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(rule_id, severity, title, rel(path, root), "secrets", line_no, line.strip()[:160], "Remove the secret, rotate it, and load it from a local or CI secret store."))
        if path.name.startswith(".env") and "=" in text:
            findings.append(Finding("AP006", "medium", "Environment file is present in the repository tree", rel(path, root), "secrets", recommendation="Commit only .env.example with safe placeholders."))
    return findings


def scan_agent_instructions(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    candidates = [root / "AGENTS.md", root / "CLAUDE.md", root / ".cursorrules", root / ".github/copilot-instructions.md"]
    rules_dir = root / ".cursor/rules"
    if rules_dir.exists():
        candidates.extend(rules_dir.rglob("*.md"))
    for path in candidates:
        if not path.exists() or not path.is_file():
            continue
        text = read_text(path)
        if text is None:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule_id, severity, title, pattern in AGENT_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(rule_id, severity, title, rel(path, root), "agent_instructions", line_no, line.strip()[:160], "Rewrite agent instructions to preserve user approval and transparent operation."))
    return findings


def load_mcp(path: Path, text: str) -> Any:
    if path.suffix == ".toml":
        return tomllib.loads(text)
    return json.loads(text)


def iter_servers(parsed: Any):
    if not isinstance(parsed, dict):
        return []
    servers = parsed.get("mcpServers") or parsed.get("servers") or parsed.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    return [(str(name), val) for name, val in servers.items() if isinstance(val, dict)]


def all_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from all_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from all_strings(v)


def scan_mcp(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for config in MCP_CONFIGS:
        path = root / config
        if not path.exists():
            continue
        text = read_text(path)
        if text is None:
            continue
        try:
            parsed = load_mcp(path, text)
        except Exception as exc:
            findings.append(Finding("AP200", "medium", "MCP config could not be parsed", rel(path, root), "mcp", evidence=str(exc)[:160], recommendation="Fix config syntax so policy checks can inspect MCP permissions."))
            continue
        for name, server in iter_servers(parsed):
            command = str(server.get("command", "")).strip()
            args = server.get("args", [])
            args_text = " ".join(str(x) for x in args) if isinstance(args, list) else str(args)
            url = str(server.get("url") or server.get("endpoint") or "")
            evidence = f"{name}: {command} {args_text}".strip()
            if command.lower() in SHELL_COMMANDS:
                findings.append(Finding("AP201", "high", "MCP server executes through a shell", rel(path, root), "mcp", evidence=evidence[:160], recommendation="Replace shell wrappers with a pinned executable and minimal arguments."))
            if DANGEROUS_ARGS.search(args_text):
                findings.append(Finding("AP202", "critical", "MCP server arguments contain destructive or remote-execution behavior", rel(path, root), "mcp", evidence=args_text[:160], recommendation="Remove destructive shell chains and require human review for dangerous commands."))
            if url and REMOTE_URL.search(url):
                severity = "medium" if "localhost" in url or "127.0.0.1" in url else "high"
                findings.append(Finding("AP204", severity, "Remote MCP endpoint configured", rel(path, root), "mcp", evidence=f"{name}: {url}"[:160], recommendation="Verify auth, scopes, TLS, redirect behavior, and private-data access."))
            if command.lower() in {"npx", "uvx", "pipx"} and "@" not in args_text:
                findings.append(Finding("AP205", "medium", "MCP server package is not version pinned", rel(path, root), "mcp", evidence=evidence[:160], recommendation="Pin MCP server package versions to reduce supply-chain drift."))
            for value in all_strings(server):
                lowered = value.strip().lower().replace("\\", "/")
                if lowered in {"/", "~", "~/", "c:/", "c:/users", "$home"} or any(part in lowered for part in SENSITIVE_PATH_PARTS):
                    findings.append(Finding("AP203", "high", "MCP server appears to expose a broad or sensitive filesystem path", rel(path, root), "mcp", evidence=f"{name}: {value}"[:160], recommendation="Scope MCP filesystem access to the minimum project directory required."))
                    break
    return findings


def scan_dependencies(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    pkg = root / "package.json"
    if pkg.exists():
        text = read_text(pkg)
        if text:
            try:
                scripts = json.loads(text).get("scripts", {})
            except json.JSONDecodeError:
                scripts = {}
            if isinstance(scripts, dict):
                for name, cmd in scripts.items():
                    cmd = str(cmd)
                    if name in {"preinstall", "install", "postinstall", "prepare"} and cmd.strip():
                        findings.append(Finding("AP300", "medium", "Lifecycle install script requires review", rel(pkg, root), "dependencies", evidence=f"{name}: {cmd}"[:160], recommendation="Keep install lifecycle scripts minimal and documented."))
                    if REMOTE_PIPE.search(cmd) or DANGEROUS_SCRIPT.search(cmd):
                        findings.append(Finding("AP301", "high", "Package script contains dangerous shell behavior", rel(pkg, root), "dependencies", evidence=f"{name}: {cmd}"[:160], recommendation="Replace dangerous shell behavior with explicit reviewable scripts."))
    for req in list(root.glob("requirements*.txt")) + list(root.glob("constraints*.txt")):
        text = read_text(req)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and UNPINNED_URL_DEP.search(stripped):
                findings.append(Finding("AP302", "medium", "Requirement uses a direct URL or Git dependency", rel(req, root), "dependencies", line_no, stripped[:160], "Pin the dependency to a trusted immutable commit or package release."))
    return findings


def scan_hygiene(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not any((root / name).exists() for name in ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]):
        findings.append(Finding("AP400", "low", "Missing SECURITY.md", ".", "repo_hygiene", recommendation="Add a SECURITY.md explaining supported versions and vulnerability reporting."))
    workflows = root / ".github/workflows"
    if not workflows.exists() or not (list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml"))):
        findings.append(Finding("AP401", "low", "No GitHub Actions workflow detected", ".github/workflows", "repo_hygiene", recommendation="Add CI that runs tests and AgentProof scans on pull requests."))
    if not (root / ".gitignore").exists():
        findings.append(Finding("AP402", "low", "Missing .gitignore", ".gitignore", "repo_hygiene", recommendation="Exclude env files, caches, build output, and private agent artifacts."))
    return findings


def scan_path(path: str | Path) -> list[Finding]:
    root = Path(path).resolve()
    findings = scan_secrets(root) + scan_mcp(root) + scan_agent_instructions(root) + scan_dependencies(root) + scan_hygiene(root)
    return sorted(findings, key=lambda f: f.sort_key)


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_severity = Counter(f.severity for f in findings)
    by_scanner = Counter(f.scanner for f in findings)
    max_severity = "info" if not findings else max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity
    return {"total": len(findings), "by_severity": dict(by_severity), "by_scanner": dict(by_scanner), "max_severity": max_severity}


def report_json(findings: list[Finding]) -> str:
    return json.dumps({"tool": "agentproof-os", "version": "0.1.0", "summary": summarize(findings), "findings": [asdict(f) for f in findings]}, indent=2, sort_keys=True)


def report_terminal(findings: list[Finding]) -> str:
    summary = summarize(findings)
    lines = ["AgentProof OS Security Report", "", f"Total findings: {summary['total']}", f"Max severity: {summary['max_severity']}", ""]
    if not findings:
        return "\n".join(lines + ["No findings detected."])
    for f in findings:
        location = f.path + (f":{f.line}" if f.line else "")
        lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.title}")
        lines.append(f"  {location}")
        if f.evidence:
            lines.append(f"  evidence: {f.evidence}")
        if f.recommendation:
            lines.append(f"  fix: {f.recommendation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def report_markdown(findings: list[Finding]) -> str:
    lines = ["# AgentProof OS Report", "", f"Total findings: **{len(findings)}**", ""]
    if not findings:
        return "\n".join(lines + ["No findings detected.", ""])
    for f in findings:
        location = f.path + (f":{f.line}" if f.line else "")
        lines += [f"## {f.rule_id} - {f.title}", "", f"- Severity: `{f.severity}`", f"- Scanner: `{f.scanner}`", f"- Location: `{location}`"]
        if f.evidence:
            lines.append(f"- Evidence: `{f.evidence}`")
        if f.recommendation:
            lines.append(f"- Recommendation: {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


def report_sarif(findings: list[Finding]) -> str:
    rules = {}
    results = []
    for f in findings:
        rules[f.rule_id] = {"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title}, "help": {"text": f.recommendation or f.title}, "properties": {"severity": f.severity, "scanner": f.scanner}}
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}.get(f.severity, "warning")
        results.append({"ruleId": f.rule_id, "level": level, "message": {"text": f.evidence or f.title}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line or 1}}}], "properties": {"severity": f.severity, "scanner": f.scanner}})
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "AgentProof OS", "rules": list(rules.values())}}, "results": results}]}, indent=2, sort_keys=True)


def render(findings: list[Finding], fmt: str) -> str:
    if fmt == "json":
        return report_json(findings)
    if fmt in {"markdown", "md"}:
        return report_markdown(findings)
    if fmt == "sarif":
        return report_sarif(findings)
    return report_terminal(findings)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="agentproof", description="Local-first safety scanner for AI-agent and MCP-enabled repositories.")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan a repository or folder")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--format", choices=["terminal", "json", "markdown", "md", "sarif"], default="terminal")
    scan.add_argument("--output", "-o")
    scan.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    mcp = sub.add_parser("mcp-audit", help="Scan only MCP configuration")
    mcp.add_argument("path", nargs="?", default=".")
    mcp.add_argument("--format", choices=["terminal", "json", "markdown", "sarif"], default="terminal")
    mcp.add_argument("--output", "-o")
    mcp.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], default="high")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command is None:
        args.command = "scan"
        args.path = "."
        args.format = "terminal"
        args.output = None
        args.fail_on = None
    findings = scan_path(args.path)
    if args.command == "mcp-audit":
        findings = [f for f in findings if f.scanner == "mcp"]
    output = render(findings, args.format)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    if args.fail_on and any(SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER[args.fail_on] for f in findings):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

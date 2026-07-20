from __future__ import annotations

import re
from pathlib import Path

PINNED_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
USES_LINE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)


def audit_text(text: str, path: str = "workflow.yml") -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for match in re.finditer(r"^\s*permissions:\s*write-all\s*$", text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "rule_id": "GHA002",
            "severity": "critical",
            "path": path,
            "line": text.count("\n", 0, match.start()) + 1,
            "message": "Replace write-all with the smallest explicit permissions map required by the workflow.",
        })
    for match in re.finditer(r"^\s*pull_request_target:\s*(?:#.*)?$", text, re.MULTILINE):
        findings.append({
            "rule_id": "GHA003",
            "severity": "high",
            "path": path,
            "line": text.count("\n", 0, match.start()) + 1,
            "message": "Review pull_request_target carefully; it runs with base-repository privileges on untrusted pull requests.",
        })
    for match in re.finditer(r"^\s*-?\s*run:\s*.*\$\{\{\s*github\.event\.pull_request\.(?:title|body|head\.ref)\s*\}\}.*$", text, re.MULTILINE):
        findings.append({
            "rule_id": "GHA004",
            "severity": "critical",
            "path": path,
            "line": text.count("\n", 0, match.start()) + 1,
            "message": "Do not interpolate untrusted pull-request text directly into a shell script; pass it through an environment variable.",
        })
    for match in re.finditer(r"^\s*-?\s*run:\s*.*(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b.*$", text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "rule_id": "GHA005",
            "severity": "critical",
            "path": path,
            "line": text.count("\n", 0, match.start()) + 1,
            "message": "Do not pipe an unverified remote response directly into a shell; download, authenticate, and execute a pinned artifact separately.",
        })
    for match in USES_LINE.finditer(text):
        target = match.group(1).strip("'\"")
        if target.startswith("./") or target.startswith("docker://") or "@" not in target:
            continue
        action, ref = target.rsplit("@", 1)
        if not PINNED_SHA.fullmatch(ref):
            line = text.count("\n", 0, match.start()) + 1
            findings.append({
                "rule_id": "GHA001",
                "severity": "high",
                "path": path,
                "line": line,
                "message": f"Pin {action} to a full 40-character commit SHA instead of {ref}.",
            })
    return findings


def audit_repository(root: str | Path) -> list[dict[str, object]]:
    root_path = Path(root).resolve()
    workflow_dir = root_path / ".github" / "workflows"
    findings: list[dict[str, object]] = []
    if not workflow_dir.is_dir():
        return findings
    for path in sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")]):
        relative = path.relative_to(root_path).as_posix()
        findings.extend(audit_text(path.read_text(encoding="utf-8", errors="replace"), relative))
    return findings


def render_markdown(findings: list[dict[str, object]]) -> str:
    lines = ["# Workflow Guard report", ""]
    if not findings:
        return "\n".join([*lines, "No tracked workflow risks found.", ""])
    lines.extend([f"Found {len(findings)} tracked risk(s).", ""])
    for item in findings:
        lines.append(
            f"- **{item['rule_id']} [{str(item['severity']).upper()}]** "
            f"`{item['path']}:{item['line']}` - {item['message']}"
        )
    lines.append("")
    return "\n".join(lines)

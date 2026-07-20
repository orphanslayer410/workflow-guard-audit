from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from workflow_guard import audit_repository, render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit GitHub workflow files for deterministic hardening risks.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--report", default="workflow-guard-report.md")
    parser.add_argument("--json", default="workflow-guard-report.json")
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()

    findings = audit_repository(args.root)
    markdown = render_markdown(findings)
    Path(args.report).write_text(markdown, encoding="utf-8")
    Path(args.json).write_text(json.dumps({"findings": findings}, indent=2) + "\n", encoding="utf-8")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(markdown)

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(f"findings={len(findings)}\n")
            handle.write(f"report={Path(args.report).as_posix()}\n")

    print(markdown)
    return 1 if findings and args.fail_on_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())

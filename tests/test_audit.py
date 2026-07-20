import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workflow_guard", ROOT / "src" / "workflow_guard.py")
workflow_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workflow_guard)


class WorkflowGuardTests(unittest.TestCase):
    def test_flags_unpinned_third_party_action(self):
        workflow = """name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        findings = workflow_guard.audit_text(workflow, "ci.yml")
        self.assertEqual(["GHA001"], [item["rule_id"] for item in findings])

    def test_flags_write_all_permissions(self):
        workflow = """name: CI
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""
        findings = workflow_guard.audit_text(workflow, "ci.yml")
        self.assertEqual(["GHA002"], [item["rule_id"] for item in findings])

    def test_flags_pull_request_target_trigger(self):
        workflow = """name: Review
on:
  pull_request_target:
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - run: echo review
"""
        findings = workflow_guard.audit_text(workflow, "review.yml")
        self.assertEqual(["GHA003"], [item["rule_id"] for item in findings])

    def test_audits_only_workflow_files_in_repository(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
            (root / "notes.yml").write_text("uses: actions/setup-python@v5\n", encoding="utf-8")
            findings = workflow_guard.audit_repository(root)
        self.assertEqual(1, len(findings))
        self.assertTrue(str(findings[0]["path"]).endswith(".github/workflows/ci.yml"))

    def test_markdown_report_includes_rule_and_location(self):
        report = workflow_guard.render_markdown([
            {"rule_id": "GHA001", "severity": "high", "path": ".github/workflows/ci.yml", "line": 6, "message": "Pin the action."}
        ])
        self.assertIn("GHA001", report)
        self.assertIn(".github/workflows/ci.yml:6", report)
        self.assertIn("Pin the action.", report)

    def test_flags_untrusted_pull_request_text_in_run_script(self):
        workflow = """jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ github.event.pull_request.title }}'
"""
        findings = workflow_guard.audit_text(workflow, "comment.yml")
        self.assertEqual(["GHA004"], [item["rule_id"] for item in findings])

    def test_flags_remote_script_piped_to_shell(self):
        workflow = """jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
"""
        findings = workflow_guard.audit_text(workflow, "install.yml")
        self.assertEqual(["GHA005"], [item["rule_id"] for item in findings])


if __name__ == "__main__":
    unittest.main()

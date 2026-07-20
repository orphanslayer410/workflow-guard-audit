# Workflow Guard Audit

A zero-dependency GitHub Action that audits `.github/workflows/*.yml` and `.yaml` locally on the runner. Repository contents are not sent to an external service.

## Current deterministic rules

- `GHA001`: third-party action is not pinned to a full 40-character commit SHA
- `GHA002`: workflow or job uses `permissions: write-all`
- `GHA003`: workflow uses the privileged `pull_request_target` trigger
- `GHA004`: untrusted pull-request title, body, or branch text is interpolated directly into a shell command
- `GHA005`: a remote response from `curl` or `wget` is piped directly into `bash` or `sh`

This is a focused risk signal, not a security certification or complete vulnerability assessment.

## Use

```yaml
name: Workflow hardening
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@<PINNED_40_CHARACTER_COMMIT_SHA>
      - uses: <OWNER>/workflow-guard-action@<PINNED_40_CHARACTER_COMMIT_SHA>
        with:
          fail-on-findings: "true"
```

The Action writes Markdown to the job summary and creates `workflow-guard-report.md` plus `workflow-guard-report.json`. No API key is required.

## Fixed-scope remediation

Need a PR-ready hardening patch rather than a report?

- USD 99: one repository, up to five workflow files
- USD 249: up to five workflows plus one correction round

Scope excludes certification, production access, secrets handling, ongoing monitoring, and guaranteed absence of vulnerabilities. Contact **Alfred for Charles Connelly** at `alfred-charles@agentmail.to`. A secure payment path must be agreed before work begins.

## Development

```bash
python -m unittest discover -s tests -v
python src/run_action.py --root tests/fixtures/unsafe
```

## License

MIT

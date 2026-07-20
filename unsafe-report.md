# Workflow Guard report

Found 5 tracked risk(s).

- **GHA002 [CRITICAL]** `.github/workflows/ci.yml:4` - Replace write-all with the smallest explicit permissions map required by the workflow.
- **GHA003 [HIGH]** `.github/workflows/ci.yml:3` - Review pull_request_target carefully; it runs with base-repository privileges on untrusted pull requests.
- **GHA004 [CRITICAL]** `.github/workflows/ci.yml:10` - Do not interpolate untrusted pull-request text directly into a shell script; pass it through an environment variable.
- **GHA005 [CRITICAL]** `.github/workflows/ci.yml:11` - Do not pipe an unverified remote response directly into a shell; download, authenticate, and execute a pinned artifact separately.
- **GHA001 [HIGH]** `.github/workflows/ci.yml:9` - Pin actions/checkout to a full 40-character commit SHA instead of v4.

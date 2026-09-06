# Repo Privacy Check

Reusable GitHub Action and workflow for detecting accidentally committed private data, credentials, host-specific configuration, and selected supply-chain indicators.

## Use the action

Pin the action to a reviewed release commit. Replace the placeholder below with the full commit SHA shown for that release. The action performs a current-tree scan by default:

```yaml
name: Privacy check

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  privacy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: 7wells/repo-privacy-check-public@<FULL_RELEASE_COMMIT_SHA>
```

The action inputs are:

| Input | Default | Purpose |
| --- | --- | --- |
| `target-path` | `.` | Repository or directory to scan |
| `scan-mode` | `current` | Scan the current tree or all Git history (`history`) |
| `include-ignored` | `false` | Include generated, dependency, cache, and Git-ignored paths |
| `report-path` | empty | Write a minimal redacted JSON report; review it before publishing |

## Reusable workflow

This repository also provides `.github/workflows/privacy-check.yml` as a reusable workflow. Call it from a workflow in the repository being checked:

```yaml
jobs:
  privacy-check:
    uses: 7wells/repo-privacy-check-public/.github/workflows/privacy-check.yml@<FULL_RELEASE_COMMIT_SHA>
```

The workflow checks out the caller repository with full history, runs current and history scans, and requires read-only repository contents permission. It does not upload reports or artifacts.

## Active rules

The scanner focuses on high-confidence privacy and secret risks:

- Private key headers, private SSH key names, key files, key stores, and `.ssh/` directories.
- Secret-bearing `.env*` files, except documented example and template variants.
- Staged or committed `.codex/` paths; their contents are not read or reported.
- Common GitHub, Slack, AWS, npm, PyPI, GitLab, Google, Stripe, and SendGrid token shapes.
- Literal credential assignments, bearer credentials, and credential-bearing URLs.
- Local credential files, Git identity values, and literal Git identity commands.
- Home-directory paths, private-network URLs, and URLs with query strings.
- Local-looking `DEV_ENV_*` assignments.
- Executable patterns that expose environments, credentials, sensitive files, diffs, or grep matches.
- Committed log files.

Unsafe-logging rules apply to executable and configuration content in the current tree. History scans retain rules for persistent secrets, credentials, private paths, and private URLs without forcing rewrites for obsolete behavioral patterns.

In Git repositories, current mode scans tracked files plus untracked files that are not excluded by standard Git ignore rules. Tracked files remain in scope even when a later ignore rule matches their path. Non-Git directories retain the regular filesystem walk. Use `include-ignored` only for deliberate audits of local generated or ignored content.

Findings contain only a rule ID, sanitized relative path, optional line number, category, and source mode. Matched content is never printed. JSON reports use the same redacted data, use mode `0600` where supported, and refuse existing symbolic-link targets.

## Local development

Requires Node.js 24 LTS and `actionlint`:

```bash
node --check scripts/privacy-check.js
bash scripts/lint-workflows.sh
npm test
npm run privacy-check
node scripts/privacy-check.js --mode history .
```

The self-check runs on pushes to `main`, pull requests, and manual dispatch. It installs actionlint v1.7.12 from the official release archive, verifies its SHA-256, runs the regression suite, exercises the current Action through `uses: ./`, and scans reachable Git history. Dependabot monitors GitHub Actions and npm metadata weekly.

## Release and rollout

Release only a reviewed `main` commit with a successful self-check. Fixed version tags are convenient references, but security-sensitive consumers should pin the release commit's full SHA and keep the version in an adjacent comment. Never use or move a major-version tag for this Action.

When scanner code changes, use two reviewed steps to avoid self-reference loops:

1. Merge and verify the implementation through local Action tests and the self-check.
2. Update the reusable workflow's internal runtime SHA in a follow-up commit and verify it again.

Test candidate rules read-only across existing consumers before release. Roll out a new public full SHA through small consumer pull requests rather than an automatic global update.

## Scope and limitations

The scanner is a focused privacy guard, not a guarantee that all sensitive data will be detected and not a replacement for secret management, dependency review, malware scanning, GitHub secret scanning, or organization policy. Review findings before publication and keep secrets out of workflow logs and reports.

## License

Released under the MIT License. See [MIT-LICENSE](MIT-LICENSE).

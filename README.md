# Repo Privacy Check

Reusable GitHub Action and workflow for detecting accidentally committed private data, credentials, host-specific configuration, and selected supply-chain indicators.

## Use the action

Pin the action to a reviewed commit or release. The action performs a current-tree scan by default:

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
      - uses: 7wells/repo-privacy-check-public@199f708994292b5565eb978e35067d4ac8c3f1df # v0.3.2
```

The action inputs are:

| Input | Default | Purpose |
| --- | --- | --- |
| `target-path` | `.` | Repository or directory to scan |
| `scan-mode` | `current` | Scan the current tree or all Git history (`history`) |
| `include-ignored` | `false` | Include generated, dependency, cache, and ignored-style directories |
| `report-path` | empty | Write a minimal redacted JSON report; review it before publishing |

## Reusable workflow

This repository also provides `.github/workflows/privacy-check.yml` as a reusable workflow. Call it from a workflow in the repository being checked:

```yaml
jobs:
  privacy-check:
    uses: 7wells/repo-privacy-check-public/.github/workflows/privacy-check.yml@199f708994292b5565eb978e35067d4ac8c3f1df # v0.3.2 workflow runtime
```

The workflow checks out the caller repository with full history, runs current and history scans, and requires read-only repository contents permission. It does not upload reports or artifacts.

## Local validation

Requires Node.js 24 or newer:

```text
node scripts/privacy-check.js --mode current .
node scripts/privacy-check.js --mode history .
```

The repository self-check runs on pushes to `main`, pull requests, and manual dispatch. GitHub Actions dependencies are monitored weekly by Dependabot. Action references are intentionally pinned to full commit SHAs; update the adjacent version comments when changing them.

## Scope and limitations

The scanner is a focused privacy guard, not a replacement for secret-management, dependency review, malware scanning, or organization policy. Review findings before publication and keep secrets out of workflow logs and reports.

## License

Released under the MIT License. See [MIT-LICENSE](MIT-LICENSE).

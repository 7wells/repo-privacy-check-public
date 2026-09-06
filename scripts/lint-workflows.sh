#!/usr/bin/env bash

# File purpose: Lint every GitHub Actions workflow without suppressing expression checks.
# Inputs: Workflow files under .github/workflows and actionlint from PATH.
# Outputs: Linter diagnostics and a nonzero exit status when any workflow is invalid.
# Side effects: None.

set -euo pipefail

for workflow in .github/workflows/*.yml .github/workflows/*.yaml; do
  if [ ! -f "$workflow" ]; then
    continue
  fi

  actionlint -no-color "$workflow"
done

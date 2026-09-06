# Repository Instructions

This repository contains a GitHub Action that audits repositories for high-confidence privacy and secret leaks. Treat changes here as security-sensitive.

## Safety Rules

- Never commit secrets, credentials, private keys, tokens, local hostnames, private URLs, local usernames, or private absolute paths.
- Scanner output must never include matched contents, secret values, environment values, file snippets, full local paths, hostnames, or URLs with query parameters.
- Findings must stay metadata-only: rule ID, relative file path, optional line number, source mode, and short category.
- Reports must remain redacted and minimal. Do not add unredacted artifacts or logs.
- Do not add telemetry, analytics, upload endpoints, or external network calls to the scanner.

## GitHub Actions Rules

- Use `permissions: contents: read` unless a stronger permission is explicitly justified.
- Do not use `pull_request_target` for untrusted code.
- Do not require repository or organization secrets.
- Pin third-party and GitHub Actions to full commit SHAs in workflow files.
- Reusable consumer workflows should check out full Git history with `fetch-depth: 0` and scan both the current tree and all reachable Git history.
- Keep `current` and `history` as separate scanner modes so each remains independently usable for local diagnostics and deliberate audits.
- If the current-tree scan fails, the reusable workflow must still run the history scan while preserving an overall failed job status.

## Scanner Behavior

- The reusable workflow is the standard consumer entry point and should scan both the current tree and full reachable Git history.
- Direct scanner invocations may use `current` for the working tree or `history` for committed Git history.
- Current-tree scans run the complete rule set and skip local/generated artifacts such as dependency directories, virtual environments, caches, logs, and build outputs by default.
- History scans enforce persistent privacy and private-data rules. Context-sensitive behavioral rules such as unsafe-logging checks are current-tree-only and must not force repository-history rewrites.
- History traversal should avoid rescanning unchanged blob/path pairs across commits so full-history checks remain practical for repositories with substantial history.
- Full-history scans are valid for deliberate audits and for this action repository's self-check workflow.
- Prefer high-confidence rules over broad speculative matches.
- Keep rule additions generic and reusable across private and public repositories.

## Required Checks

Run these before committing scanner, workflow, README, package, or test changes:

```bash
node --check scripts/privacy-check.js
npm test
npm run privacy-check
node scripts/privacy-check.js --mode history .
```

Validate modified shell snippets or shell scripts with `bash -n`.

## Documentation

- Keep repository documentation in English.
- Document safe usage for beginners without exposing sensitive examples.
- Consumer examples must use full public release-commit SHA placeholders, not branch names, stale concrete SHAs, or moving tags.
- Explain that the reusable workflow performs both current-tree and full-history scans, while direct action use can still select `current` or `history` explicitly.
- Explain which rule classes are intentionally current-tree-only versus history-relevant.

## File Headers

- Add a short English header to handwritten, commentable files with non-obvious behavior.
- Include `File purpose` and only relevant optional fields: `Inputs`, `Outputs`, `Side effects`, `Security and privacy`, and `Maintenance invariants`.
- In scripts, place the header immediately after the shebang.
- Do not add artificial headers to self-explanatory files, README files, simple configuration, JSON, lockfiles, generated files, binary files, or standardized license texts.
- Keep headers concise and update them when their described behavior changes.

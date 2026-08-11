---
title: "Pre-commit Hook"
description: "Use the Leakwatch pre-commit hook to scan for secrets before every commit."
---

# Pre-commit Hook

The cheapest time to catch a secret is before it enters the repository at all. Leakwatch ships a native [pre-commit](https://pre-commit.com) hook that runs `leakwatch scan fs` automatically on every `git commit`, so a leaked API key or password fails the commit rather than appearing in history.

## Prerequisites

You need:

- Python 3.8+ (pre-commit is a Python tool).
- [pre-commit](https://pre-commit.com/#install) installed globally (`pip install pre-commit` or `brew install pre-commit`).
- Go 1.25+ on `PATH` — the hook language is `golang`, so pre-commit compiles Leakwatch from source on first run.

## Configuration

Add a `.pre-commit-config.yaml` file to the root of your repository (or extend an existing one):

```yaml
repos:
  - repo: https://github.com/HodeTech/Leakwatch
    rev: v1.7.0
    hooks:
      - id: leakwatch
```

Install the hooks into the local Git repo:

```bash
pre-commit install
```

That is all. From this point on, every `git commit` triggers a filesystem scan. If Leakwatch finds any secrets, the commit is blocked and the findings are printed to the terminal.

## Running manually

To scan the entire repository (not just staged files) at any time:

```bash
pre-commit run --all-files
```

To run only the Leakwatch hook without triggering others:

```bash
pre-commit run leakwatch --all-files
```

## Passing extra arguments

The hook's default behavior matches `leakwatch scan fs` with no additional flags. You can pass extra arguments via the `args:` key:

```yaml
repos:
  - repo: https://github.com/HodeTech/Leakwatch
    rev: v1.7.0
    hooks:
      - id: leakwatch
        args:
          - --only-verified
          - --min-severity
          - high
```

This example reports only high-severity secrets that Leakwatch has confirmed are still active — a strict policy suitable for teams that want to avoid false-positive noise without sacrificing coverage.

Other useful arguments:

```yaml
args:
  - --no-verify          # skip live verification for faster commits
  - --min-severity
  - medium               # suppress low-severity noise
  - --format
  - table                # human-readable output in the terminal
```

:::note
`pass_filenames: false` is set in the hook definition, which means the hook always scans the full working tree rather than only the files staged for the current commit. This guarantees that secrets already present in unstaged files are also detected.
:::

## What the hook scans

The hook runs `leakwatch scan fs` against the repository working directory. It uses the same detection pipeline as the CLI: Aho-Corasick pre-filtering, regex validation, entropy calculation, and (unless `--no-verify` is set) live verification.

Configuration in `.leakwatch.yaml` is respected automatically — exclusion patterns, entropy thresholds, and verification settings all apply without any extra hook configuration.

## Skipping the hook temporarily

To commit without running the hook (for example, when committing a controlled test fixture that contains a redacted secret):

```bash
SKIP=leakwatch git commit -m "chore: add test fixture"
```

:::warn
Using `SKIP=leakwatch` bypasses all secret scanning for that commit. Use it only when you have confirmed the content is safe, and prefer `.leakwatchignore` or inline `leakwatch:ignore` comments for permanent suppressions instead.
:::

## Keeping the hook version pinned

Pin `rev:` to a specific tag rather than a branch name. This ensures all developers on the team use the same detector set and the hook does not silently upgrade mid-sprint:

```yaml
rev: v1.7.0   # pin; do not use 'main' or 'HEAD'
```

Update by running:

```bash
pre-commit autoupdate
```

which bumps `rev` to the latest tag and lets you review the change before committing it.

## See also

- [Filesystem Scanning](#/scanning/filesystem) — the underlying scan command the hook runs.
- [Configuration File](#/configuration/config-file) — control exclusions, entropy, and verification in `.leakwatch.yaml`.
- [GitHub Action](#/ci-cd/github-action) — scan on every push and pull request in GitHub CI.
- [Exit Codes](#/reference/exit-codes) — how exit codes map to scan outcomes.

---
title: "Git History"
description: "Scan the full commit history of a local or remote Git repository for leaked secrets."
---

# Git History

A secret that was committed and then deleted is still present in every earlier commit, reachable to anyone with repository access. `leakwatch scan git` walks the *entire* commit history of a repository — local or remote — and surfaces those secrets before they can be exploited.

## Basic usage

```bash
leakwatch scan git <url_or_path>
```

The command takes exactly one argument: either a **local filesystem path** to a repository (`.` for the current directory) or a **remote HTTP/HTTPS or SSH URL**.

Leakwatch uses [go-git](https://github.com/go-git/go-git) for all Git operations — a pure Go implementation with no dependency on a system `git` binary.

```bash
# Scan the local repository in the current directory
leakwatch scan git .

# Scan a remote repository over HTTPS
leakwatch scan git https://github.com/org/repo.git

# Scan over SSH
leakwatch scan git git@github.com:org/repo.git
```

## How it scans

Leakwatch walks every commit in the history and examines the blobs introduced by each commit. **Blob-hash deduplication** ensures that identical file content is scanned only once, no matter how many commits reference it. This keeps scan time proportional to the *unique content* in the repository rather than to the raw commit count.

:::note
Because Leakwatch examines commit-by-commit diffs, it finds secrets that were introduced and later deleted — content that is invisible in the current working tree.
:::

## Flags

### Git-specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--since` | string (YYYY-MM-DD) | — | Scan only commits after this date. |
| `--since-commit` | string | — | Scan only changes from this commit hash to HEAD (diff-based). |
| `--branch` | string | — | Target a specific branch instead of the default. |
| `--depth` | int | `0` (full) | Clone depth for **remote repositories only**. `0` means full history. |

### Common scan flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Skip blobs larger than this value (bytes). |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--exclude` | — | — | Path pattern to exclude. Repeatable; combined with `filter.exclude-paths`. |
| `--exclude-detectors` | — | — | Detector IDs to exclude for this run. Repeatable; combined with `filter.exclude-detectors`. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Root-level flags `--config` and `--log-level` (default `warn`) also apply.

## Examples

Scan the full history of the local repository and print a table:

```bash
leakwatch scan git . --format table
```

Scan only commits made after a specific date on the `develop` branch:

```bash
leakwatch scan git . --since 2026-02-23 --branch develop
```

Scan changes introduced since a specific commit (useful in CI to check only new commits):

```bash
leakwatch scan git . --since-commit a1b2c3d
```

Do a shallow clone of a large remote repository to speed up the initial scan:

```bash
leakwatch scan git https://github.com/org/repo.git --depth 50
```

Scan a remote repository and save verified findings only as SARIF:

```bash
leakwatch scan git https://github.com/org/repo.git \
  --only-verified \
  --format sarif \
  --output git-results.sarif
```

## Finding metadata

Each finding from a Git scan includes commit metadata:

| Field | Description |
|-------|-------------|
| `repository` | URL or path of the scanned repository (credentials stripped). |
| `commit` | Commit hash where the secret was introduced. |
| `author` | Commit author's name only. |
| `email` | Commit author's email address, as a separate field. |
| `date` | Commit timestamp. |
| `branch` | Branch context (when available). |

:::tip
Use `--since-commit` in pull-request CI jobs to scan only the commits added by the PR. Use `--since <date>` for scheduled nightly scans covering recent activity.
:::

## Credential safety

When a repository URL contains embedded credentials (for example `https://user:TOKEN@host/repo.git`), Leakwatch strips those credentials before writing anything to logs or output, so the token never appears in scan results or CI traces.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, findings reported. |
| `2` | Scan failed (invalid URL, authentication error, etc.). |
| `3` | Scan was interrupted (`Ctrl+C` / `SIGTERM`) before completing, and no findings had been reported. |

A scan summary is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

## See also

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Multiple Repositories](#/scanning/multiple-repos) — scan several repositories in one command.
- [Filesystem](#/scanning/filesystem) — scan the working tree instead of history.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [Ignoring Findings](#/configuration/ignoring-findings) — suppress known false positives.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.

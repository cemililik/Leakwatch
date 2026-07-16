---
title: "Multiple Repositories"
description: "Scan several Git repositories concurrently and combine results into a single report."
---

# Multiple Repositories

When an organization grows, secrets can land in any of dozens or hundreds of repositories. Checking them one by one is impractical. `leakwatch scan repos` accepts multiple repository URLs and scans them concurrently, merging all findings into a single output — one command, one report.

## Basic usage

```bash
leakwatch scan repos <url1> <url2> [url...]
```

The command requires **at least two** repository URLs. All repositories are cloned, scanned, and cleaned up automatically. The combined finding count and a single scan summary are reported at the end.

```bash
leakwatch scan repos \
  https://github.com/org/api.git \
  https://github.com/org/web.git
```

## How it works

Leakwatch spawns up to `--parallel` repository scans at once. Each repository is:

1. Cloned from the provided URL (credentials are stripped from logs and output for safety).
2. Scanned with the full detection pipeline, using `--concurrency` workers for that repository.
3. Cleaned up (the temporary clone is deleted) once the scan completes.

All findings from all repositories are collected and written as a single output, as if the scan had been a single-source run. The displayed target is `<N> repositories`.

## Flags

### Multi-repo-specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--parallel` | int | `3` | Number of repositories to scan in parallel. |

### Common scan flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers **per repository**. |
| `--max-file-size` | — | `10485760` (10 MB) | Skip blobs larger than this value (bytes). |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--exclude` | — | — | Path pattern to exclude from every repository's scan. Repeatable; combined with `filter.exclude-paths`. |
| `--exclude-detectors` | — | — | Detector IDs to exclude for this run (e.g. `aws-access-key-id`). Repeatable; combined with `filter.exclude-detectors`. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Path exclusions from `filter.exclude-paths` in `.leakwatch.yaml` (or `--exclude`) apply to all repositories. Root-level flags `--config` and `--log-level` (default `warn`) also apply.

## Examples

Scan two repositories and display results as a table:

```bash
leakwatch scan repos \
  https://github.com/org/api.git \
  https://github.com/org/web.git \
  --format table
```

Scan five repositories with higher parallelism and save the combined results as SARIF:

```bash
leakwatch scan repos \
  https://github.com/org/api.git \
  https://github.com/org/web.git \
  https://github.com/org/infra.git \
  https://github.com/org/mobile.git \
  https://github.com/org/docs.git \
  --parallel 4 \
  --format sarif \
  --output all-repos.sarif
```

Scan with more workers per repository and show only verified findings:

```bash
leakwatch scan repos \
  https://github.com/org/backend.git \
  https://github.com/org/frontend.git \
  --concurrency 8 \
  --only-verified \
  --format json \
  --output verified-findings.json
```

## Tuning parallelism

Two knobs control throughput:

- `--parallel` controls how many repository clones and scans run simultaneously. The default of `3` is appropriate for most workloads. Raise it when network bandwidth and CPU headroom allow; lower it on constrained machines.
- `--concurrency` (`-c`) controls how many worker goroutines process file blobs *within* each individual repository. This is the same flag available on all scan commands.

Total concurrent operations at peak = `--parallel` × `--concurrency`.

:::note
If one or more repository scans fail (for example, due to a network error or authentication failure), Leakwatch logs the error and continues scanning the remaining repositories. **Findings take precedence**: if any finding survives filtering across the whole run, the exit code is `1` even though some repositories failed to scan. Exit code `2` (repository scan failure) is only returned when zero findings were reported overall.
:::

## Credential safety

Any embedded credentials in repository URLs (e.g. `https://user:TOKEN@host/repo.git`) are stripped before the URL is written to logs, output, or the scan summary.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | All repository scans completed, no findings. |
| `1` | One or more findings survived filtering — returned even if some repositories failed to scan or the run was interrupted, so a "secrets found" signal is never masked by an unrelated failure. |
| `2` | Zero findings were reported and one or more repository scans failed, or a configuration error occurred. |
| `3` | The run was interrupted (`Ctrl+C` / `SIGTERM`) before completing and zero findings had been reported. |

A scan summary is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

## See also

- [Git History](#/scanning/git-history) — scan a single repository in depth.
- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Config File](#/configuration/config-file) — configure shared defaults for all sources.
- [Ignoring Findings](#/configuration/ignoring-findings) — suppress known false positives.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.

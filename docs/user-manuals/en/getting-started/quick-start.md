---
title: "Quick Start"
description: "Run your first Leakwatch scan in under a minute."
---

# Quick Start

The fastest way to understand what Leakwatch can do is to point it at a real directory. This page walks you through your first scan, explains what the output means, and shows the flags you will reach for most often.

## Prerequisites

Leakwatch must be installed and accessible on your `PATH`. If you have not done that yet, see [Installation](#/getting-started/installation).

## Your first scan

Scan the current directory with one command:

```bash
leakwatch scan fs .
```

By default, output is JSON written to stdout. To get a human-readable, colorized table instead, add `--format table`:

```bash
leakwatch scan fs . --format table
```

Here is what a result looks like (the table formatter always prints a trailing REMEDIATION column; it shows `-` unless `--remediation` is also set):

```text
SEVERITY  DETECTOR           FILE                       LINE  REDACTED      STATUS           REMEDIATION
--------  --------           ----                       ----  --------      ------           -----------
CRITICAL  aws-access-key-id  config/deploy.env          12    ****MNOP      verified_active   -
HIGH      npm-token          scripts/bootstrap.sh       37    npm_****wxyz  verified_active   -
MEDIUM    generic-api-key    src/services/analytics.js  89    ****w2y4      unverified        -

Found 3 secrets (1 critical, 1 high, 1 medium).

── Scan Summary ─────────────────────────────────
  Date:            2026-05-23 14:03:11
  Source:          filesystem
  Target:          /home/user/myproject
  Files scanned:   312
  Duration:        1.24s
  Findings:        3
─────────────────────────────────────────────────
```

The scan summary is always printed to **stderr**, so it never interferes with piped or redirected output.

## Understanding a finding

Each row in the table (or object in JSON) represents one finding. The key fields are:

| Field | Meaning |
|-------|---------|
| **SEVERITY** | How critical the secret type is: `low`, `medium`, `high`, or `critical` |
| **DETECTOR** | The detector that matched — identifies the secret type (e.g. `aws-access-key-id`) |
| **FILE** | Path to the file where the secret was found, relative to the scan root |
| **LINE** | Line number of the match |
| **REDACTED** | A masked representation of the secret — never the raw value unless `--show-raw` is set |
| **STATUS** | Verification outcome: `verified_active`, `verified_inactive`, `unverified`, or `verify_error` |
| **REMEDIATION** | Rotation/revocation guidance title, or `-` when `--remediation` was not passed |

A `verified_active` status means Leakwatch confirmed the secret is still live with a contract-valid, non-destructive provider check. **Treat every `verified_active` finding as an open incident.**

## Common scan options

### Focus on confirmed secrets only

```bash
leakwatch scan fs . --only-verified
```

This hides unverified and inactive findings, leaving only those confirmed live. Useful for triage when you have many results.

### Skip network verification for a fast offline scan

```bash
leakwatch scan fs . --no-verify
```

Verification is skipped entirely — no outbound network calls are made. Results appear faster and work without internet access, but all findings are marked `unverified`.

### Add remediation guidance

```bash
leakwatch scan fs . --remediation --format table
```

Each finding gains a **REMEDIATION** column explaining how to rotate or revoke the specific secret type. The same data is included in JSON, SARIF, and CSV output when the flag is set.

### Filter by minimum severity

```bash
leakwatch scan fs . --min-severity high
```

Only findings at `high` or `critical` severity are reported.

### Save results to a file

```bash
leakwatch scan fs . --format sarif --output results.sarif
```

The `--output` / `-o` flag writes to a file instead of stdout. SARIF output is compatible with [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning).

## Generate a configuration file

Running Leakwatch with defaults is fine for a first try, but for repeated use you will want a project-level configuration:

```bash
leakwatch init
```

This writes `.leakwatch.yaml` in the current directory with recommended defaults for concurrency, entropy, verification, output format, and common path exclusions. Use `--force` to overwrite an existing file, or `--output` to write to a different path.

See [Configuration File](#/configuration/config-file) for a full explanation of every option.

## Exit codes

Leakwatch uses distinct exit codes so CI scripts can act on results without parsing output:

| Code | Meaning |
|------|---------|
| `0` | Scan completed — no findings |
| `1` | Scan completed — one or more secrets found |
| `2` | Scan failed due to an error |
| `3` | Scan was interrupted (`Ctrl+C` / `SIGTERM`) before it completed, and no findings had been reported yet |

A typical CI gate looks like:

```bash
leakwatch scan fs . --only-verified --format sarif --output results.sarif
if [ $? -eq 1 ]; then
  echo "Active secrets found — failing build"
  exit 1
fi
```

:::warn
Exit code `1` is returned whenever *any* finding passes the active filters (including `--min-severity` and `--only-verified`). A clean exit code `0` means no findings matched — not that no secrets exist in the codebase.
:::

## Cancelling a scan

Press `Ctrl+C` (or send `SIGTERM`) to cancel a running scan. Leakwatch stops gracefully: in-flight chunks finish, partial results are written, and the summary indicates `Status: interrupted (partial results)`. Findings still take precedence over interruption — if secrets were already found before the interrupt, the scan exits `1` so that signal is never masked. Exit code `3` is returned only when the scan was interrupted with zero findings reported, so a CI pipeline can never mistake a scan that did not finish for a clean pass.

## See also

- [Installation](#/getting-started/installation)
- [How It Works](#/getting-started/how-it-works)
- [CLI Reference](#/reference/cli-reference)
- [Configuration File](#/configuration/config-file)
- [How Verification Works](#/verification/how-verification-works)

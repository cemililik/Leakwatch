---
title: "Configuration File"
description: "How to configure Leakwatch with .leakwatch.yaml — full schema, defaults, validation rules, environment overrides, and the leakwatch init command."
---

# Configuration File

Leakwatch's behaviour across every scan command is driven by a single YAML file named `.leakwatch.yaml`. Understanding this file lets you tune concurrency, verification, output format, and path filtering once — and have every scan pick it up automatically.

## File discovery

Leakwatch resolves the config file in the following order:

1. **`--config <path>` flag** — use an explicit path regardless of the working directory.
2. **Current directory** — `.leakwatch.yaml` in the directory where the command is run.
3. **Home directory** — `~/.leakwatch.yaml` as a fallback.

If no file is found, built-in defaults are used for every setting. If a file **is** found (or `--config` points at one) but fails to parse as valid YAML, that is a fatal error — the scan does not silently fall back to defaults, since doing so could silently widen detection scope beyond what the operator configured.

## Generating a starter file

The `leakwatch init` command writes a ready-to-edit file with recommended defaults:

```bash
leakwatch init
```

By default the file is written to `.leakwatch.yaml` in the current directory. Use `--output` to choose a different path:

```bash
leakwatch init --output /etc/leakwatch/.leakwatch.yaml
```

If the target file already exists, `leakwatch init` will refuse to overwrite it and exit with an error. Pass `--force` to overwrite:

```bash
leakwatch init --force
```

## Environment variable overrides

Every config key can be overridden with an environment variable. The naming rule is:

- Prefix: `LEAKWATCH_`
- Replace `.` and `-` with `_`
- Uppercase

Examples:

| Config key | Environment variable |
|---|---|
| `scan.concurrency` | `LEAKWATCH_SCAN_CONCURRENCY` |
| `verification.rate-limit` | `LEAKWATCH_VERIFICATION_RATE_LIMIT` |
| `output.format` | `LEAKWATCH_OUTPUT_FORMAT` |
| `detection.entropy.threshold` | `LEAKWATCH_DETECTION_ENTROPY_THRESHOLD` |

## Precedence

When the same setting is specified in multiple places, the highest-priority source wins:

1. Command-line flag (highest)
2. Environment variable
3. Config file value
4. Built-in default (lowest)

## Full schema

The annotated schema below shows every supported key, its default value, and valid range.

```yaml
# ── Scan engine ──────────────────────────────────────────────────────────────

scan:
  # Number of concurrent file-processing workers.
  # Defaults to the number of logical CPU cores on the host.
  # Must be >= 1.
  concurrency: 8

  # Maximum file size to scan, in bytes. Files larger than this limit are
  # skipped entirely. Default is 10 MB (10485760). Must be >= 1.
  max-file-size: 10485760

# ── Detection ─────────────────────────────────────────────────────────────────

detection:
  entropy:
    # Enable Shannon entropy calculation for each candidate match.
    enabled: true

    # Entropy threshold used for display, and to gate the built-in
    # generic-api-key detector plus any custom rule with its own entropy field.
    # Range: 0–8. Default: 4.0.
    # See note below about built-in findings.
    threshold: 4.0

# ── Verification ─────────────────────────────────────────────────────────────

verification:
  # Enable live verification against provider APIs.
  enabled: true

  # Per-finding verification-operation timeout, including bounded fallback and
  # request admission. Must be >= 1ms when verification is enabled.
  # Use a duration string (e.g. "10s", "500ms") — a bare integer is
  # treated as nanoseconds and will fail validation.
  timeout: 10s

  # Number of concurrent verification workers. Must be >= 1.
  concurrency: 4

  # Maximum verification requests per second (token-bucket rate limiter).
  # Must be > 0.
  rate-limit: 10.0

# ── Filtering ─────────────────────────────────────────────────────────────────

filter:
  # Glob patterns for paths to exclude from scanning.
  # Supported glob styles: filepath.Match patterns, ** double-star spanning
  # zero or more path segments, and trailing-slash dir/ patterns that match
  # the named directory at any depth. Each pattern is tested against both the
  # full path and the base filename, so simple patterns like "*.min.js" match
  # nested files without a leading path prefix.
  # Applies to all scan sources. (The --exclude flag, available on every scan
  # subcommand except `scan slack`, adds to this list at run time rather than
  # replacing it.)
  # Default: [] (no exclusions beyond the built-in binary/lock-file skips).
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "go.sum"
    - "package-lock.json"
    - "yarn.lock"

  # Detector IDs to disable entirely. Findings from listed detectors are never
  # produced regardless of other settings. Default: [].
  # The --exclude-detectors flag, available on every scan subcommand, adds to
  # this list at run time rather than replacing it.
  exclude-detectors: []

# ── Output ────────────────────────────────────────────────────────────────────

output:
  # Output format. One of: json, sarif, csv, table, github. Default: json.
  # The --format / -f flag overrides this at run time.
  format: json

  # Write output to this file path instead of stdout. Default: "" (stdout).
  # The --output / -o flag overrides this at run time. A bare path with no
  # extension is auto-suffixed with the format's own extension, and the file
  # is written with 0600 permissions. Ignored when format is "github", which
  # always writes to stdout.
  file: ""

  # Drop findings below this severity level.
  # One of: low, medium, high, critical. Default: "" (show all).
  # The --min-severity flag overrides this at run time.
  severity-threshold: ""

  # Include the unredacted secret value in output.
  # Default: false. The --show-raw flag overrides this at run time.
  show-raw: false

# ── Custom rules ──────────────────────────────────────────────────────────────

# Define your own detectors as YAML rules. See the custom rules page for the
# full rule schema.
# custom-rules:
#   - id: "my-internal-token"
#     description: "Internal Service Token"
#     regex: "mycompany_[a-zA-Z0-9]{32}"
#     keywords: ["mycompany_"]
#     severity: critical
custom-rules: []
```

:::note
`detection.entropy.enabled` controls whether a computed entropy value is present alongside findings. `detection.entropy.threshold` does not control display; it gates detectors that opt into engine entropy heuristics — currently only the built-in `generic-api-key` detector. A match whose entropy falls below that threshold is suppressed as a likely placeholder. Custom rules that declare an `entropy` field apply their own independent per-rule threshold. Every structural/format-anchored built-in detector — `aws-access-key-id`, `github-token`, and the rest — is **never** dropped by the engine threshold, regardless of entropy.
:::

## Validation

Leakwatch validates the loaded configuration before starting a scan and exits with an error for any of the following:

| Condition | Error |
|---|---|
| `scan.concurrency < 1` | Invalid concurrency value |
| `scan.max-file-size < 1` | Invalid max-file-size value |
| `output.format` not in `json\|sarif\|csv\|table\|github` | Unsupported output format |
| `detection.entropy.threshold` outside 0–8 | Invalid entropy threshold |
| `output.severity-threshold` not a valid level (when non-empty) | Invalid severity-threshold |
| `verification.timeout < 1ms` (when verification enabled) | Invalid verification timeout |
| `verification.concurrency < 1` (when verification enabled) | Invalid verification concurrency |
| `verification.rate-limit <= 0` (when verification enabled) | Invalid verification rate-limit |

## See also

- [Ignoring Findings](#/configuration/ignoring-findings)
- [Severity & Filtering](#/configuration/severity-and-filtering)
- [Custom Rules](#/detectors/custom-rules)
- [Environment Variables](#/reference/environment-variables)

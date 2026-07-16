---
title: "Severity & Filtering"
description: "Control which findings reach your output using severity thresholds, verified-only mode, detector exclusions, and path exclusions."
---

# Severity & Filtering

A busy codebase can produce many findings. Leakwatch provides several independent filters you can combine to focus on the signals that matter most: severity thresholds drop low-priority noise, verified-only mode surfaces only confirmed live secrets, detector exclusions silence known false-positive sources, and path exclusions remove entire directory trees from scope.

## Severity levels

Every built-in detector ships with a default severity. The four levels, from lowest to highest priority, are:

| Level | Typical use |
|---|---|
| `low` | Generic patterns with a higher false-positive rate |
| `medium` | Recognizable credential formats, unconfirmed |
| `high` | Well-structured secrets where exposure is likely significant |
| `critical` | Live secrets confirmed or formats with near-zero false-positive rates |

The severity assigned to each detector is listed in the [Detector Catalog](#/detectors/detector-catalog).

## `--min-severity`: drop findings below a threshold

Pass `--min-severity <level>` to discard findings whose severity is below the specified level. Only findings at or above the threshold reach the output.

```bash
# Show only high and critical findings
leakwatch scan fs . --min-severity high

# Show medium, high, and critical findings
leakwatch scan fs . --min-severity medium
```

You can set a persistent default in the config file under `output.severity-threshold`. The `--min-severity` flag overrides the config value at run time:

```yaml
output:
  severity-threshold: medium
```

## `--only-verified`: confirmed active secrets only

Pass `--only-verified` to keep only findings whose verification status is `verified_active` — secrets that Leakwatch confirmed are still valid by making a controlled read-only call to the provider API. All other findings (`unverified`, `verified_inactive`, or `verify_error`) are dropped.

```bash
leakwatch scan fs . --only-verified
```

This flag is most useful in CI pipelines where you want to fail the build **only** on confirmed incidents, not on suspicious patterns that may be placeholders or already-rotated credentials.

See [How Verification Works](#/verification/how-verification-works) for which detectors support live verification.

## `filter.exclude-detectors`: disable specific detectors

To permanently disable one or more detectors, list their IDs under `filter.exclude-detectors` in the config file. Findings from listed detectors are never produced, regardless of any other setting:

```yaml
filter:
  exclude-detectors:
    - generic-api-key
    - jwt
```

Detector IDs are listed in the [Detector Catalog](#/detectors/detector-catalog). Use this setting when a detector consistently produces false positives for your codebase and other suppression mechanisms (inline ignores or `.leakwatchignore`) are not granular enough.

To silence a detector for a single run without editing the config file, pass `--exclude-detectors <id>[,<id>...]` (repeatable) on any scan subcommand. It adds to `filter.exclude-detectors` rather than replacing it.

## `filter.exclude-paths`: skip paths before scanning

To exclude paths before the scan engine reads them, use `filter.exclude-paths` in the config file. The patterns use the same glob syntax as `.leakwatchignore` (standard globs, `**` double-star, and trailing-slash directory patterns), and apply to **all scan sources**:

```yaml
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "test/fixtures/"
```

:::note
The `--exclude <pattern>` flag is the command-line equivalent of `filter.exclude-paths`, and is available on every scan subcommand **except** `scan slack` (which excludes by `--exclude-channels` instead). It is repeatable and adds to `filter.exclude-paths` rather than replacing it.
:::

## Combining filters in CI

In a CI pipeline you typically want a low-noise, high-signal run that fails only on real incidents. A recommended combination:

```bash
leakwatch scan fs . \
  --only-verified \
  --min-severity high \
  --format sarif \
  --output results.sarif
```

With a config file handling the persistent path exclusions:

```yaml
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "test/fixtures/"
  exclude-detectors:
    - generic-api-key

output:
  severity-threshold: high
```

Then override just the format and destination at the command line for CI:

```bash
leakwatch scan fs . --only-verified --format sarif --output results.sarif
```

See [How Verification Works](#/verification/how-verification-works) for verification details, [Ignoring Findings](#/configuration/ignoring-findings) for inline and file-based suppression, and [Configuration File](#/configuration/config-file) for the full schema.

## See also

- [Detector Catalog](#/detectors/detector-catalog)
- [How Verification Works](#/verification/how-verification-works)
- [Configuration File](#/configuration/config-file)
- [Ignoring Findings](#/configuration/ignoring-findings)

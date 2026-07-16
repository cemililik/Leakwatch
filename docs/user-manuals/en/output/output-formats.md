---
title: "Output Formats"
description: "The five output formats Leakwatch supports — JSON, SARIF, CSV, table, and GitHub annotations — with examples and guidance on when to use each."
---

# Output Formats

Leakwatch supports five output formats, covering machine-readable pipelines, security tooling integrations, spreadsheet exports, human-readable terminal review, and GitHub Actions annotations. Select a format with `--format` (or `-f`); write to a file instead of stdout with `--output` (or `-o`).

```bash
leakwatch scan fs . --format json
leakwatch scan fs . --format sarif --output results.sarif
leakwatch scan fs . --format csv   --output findings.csv
leakwatch scan fs . --format table
leakwatch scan fs . --format github   # GitHub Actions annotations (CI use)
```

The default format is `json`.

## JSON

JSON is the default format and the most complete representation. Leakwatch writes a JSON **array** of finding objects to stdout (or to the file given by `--output`).

The raw secret value is **never** serialized unless `--show-raw` is explicitly set. With `--show-raw`, a `"raw"` field is added to each object.

### Example invocation

```bash
leakwatch scan fs ./src --format json --output findings.json
```

### Example finding object

```json
{
  "id": "447b5d2846d08ce25dd3d638cfe911ad",
  "detector_id": "github-token",
  "severity": "critical",
  "redacted": "ghp_****************************Xk9R",
  "source": {
    "source_type": "filesystem",
    "file_path": "scripts/deploy.sh",
    "line": 14
  },
  "verification": {
    "status": "verified_active"
  },
  "entropy": 5.82,
  "detected_at": "2026-05-23T10:15:30Z"
}
```

`id` is a deterministic, truncated SHA-256 rendered as a flat 32-character lowercase hex string — it is **not** a UUID and never contains dashes. See [How It Works](#/getting-started/how-it-works) for how it is computed.

When `--remediation` is also set, a `"remediation"` object is nested inside each finding. See [Remediation Guidance](#/output/remediation).

## SARIF

The `sarif` format produces a SARIF v2.1.0 document, designed for upload to [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github). The tool name is `Leakwatch` and `informationUri` points to `https://github.com/HodeTech/Leakwatch`.

Each detector that appears in the findings becomes a **rule** in the SARIF driver, complete with `help` text (populated from remediation steps when `--remediation` is set) and a `helpUri` pointing to the provider documentation. Results carry a `leakwatch/v1` partial fingerprint computed from the detector ID, redacted value, and file path — this lets GitHub Code Scanning track the same alert even when surrounding code shifts.

### Example invocation

```bash
leakwatch scan fs . --format sarif --output results.sarif
```

### Uploading to GitHub Code Scanning

```yaml
# In a GitHub Actions workflow step:
- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [GitHub Action](#/ci-cd/github-action) for the full CI setup.

## CSV

The `csv` format writes a header row followed by one row per finding, using standard comma-separated values. Every cell is sanitized against spreadsheet formula injection before writing.

**Columns (default):**

```text
id,detector_id,severity,redacted,source,file_path,line,commit,verification_status,remediation
```

`source` is a human-readable label identifying the origin repository, container image, or Slack channel a finding came from (useful when a `scan repos` run combines findings from several repositories into one CSV); it is empty for a plain filesystem scan of a single directory. `line` is the line number, empty when not applicable.

When `--show-raw` is set, a trailing `raw` column is appended.

The `remediation` column contains the remediation title (e.g. `"Revoke GitHub Token"`) when `--remediation` is set, and is empty otherwise.

### Example invocation

```bash
leakwatch scan git . --format csv --output findings.csv
```

### Example output

```csv
id,detector_id,severity,redacted,source,file_path,line,commit,verification_status,remediation
447b5d2846d08ce25dd3d638cfe911ad,github-token,critical,ghp_****Xk9R,,scripts/deploy.sh,14,7d3e1f2,verified_active,Revoke GitHub Token
e6fa909746d7d5242309b64c33209fa9,aws-access-key-id,high,AKIA****K7NP,,config/aws.yml,3,7d3e1f2,unverified,Rotate AWS Access Key
```

## Table

The `table` format writes a human-readable tab-aligned table, best suited for interactive terminal sessions where you want a quick visual scan of the results.

**Columns:**

```text
SEVERITY | DETECTOR | FILE | LINE | REDACTED | STATUS | REMEDIATION
```

The `LINE` column shows `-` when no line number is available (for example a Slack or container-image finding). The `REMEDIATION` column is always present and shows `-` unless `--remediation` is set. When `--show-raw` is also set, a trailing `RAW` column is appended. A summary line is printed at the bottom of the table (e.g. `Found 3 secrets (1 critical, 2 high).`).

Attacker-influenced fields (detector ID, file path, redacted value) are stripped of control characters and ANSI escape sequences before being written to the terminal, so a maliciously crafted file name or custom-rule match cannot inject escape sequences into your terminal session.

**ANSI color** is applied to the `SEVERITY` column automatically, but only when all four conditions are met:

1. `--format table` is selected
2. Output goes to stdout (no `--output <file>`)
3. stdout is a TTY (not a pipe or redirect)
4. The `NO_COLOR` environment variable is unset

| Severity | Color |
|---|---|
| `critical` | Bold red |
| `high` | Red |
| `medium` | Yellow |
| `low` | Blue |

### Example invocation

```bash
leakwatch scan fs . --format table --min-severity high
```

### Example output

```text
SEVERITY  DETECTOR           FILE                LINE  REDACTED      STATUS           REMEDIATION
--------  --------           ----                ----  --------      ------           -----------
CRITICAL  github-token       scripts/deploy.sh   14    ghp_****Xk9R  verified_active  Revoke GitHub Token
HIGH      aws-access-key-id  config/aws.yml      3     AKIA****K7NP  unverified       Rotate AWS Access Key

Found 2 secrets (1 critical, 1 high).
```

## GitHub annotations

The `github` format emits [GitHub Actions workflow commands](https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions) (`::error` / `::warning` / `::notice`) so findings appear as **inline annotations** on a pull request's *Files changed* view and in the run log. It is intended to be streamed to the runner's stdout — writing it to a file has no effect.

Severity maps to the annotation level: `critical` → `error`, `high` → `warning`, `medium`/`low` → `notice`. A finding with a file path is anchored to that file and line; a finding without one becomes a run-level annotation.

For safety, this format **never** prints the raw secret — only the redacted value is shown, even with `--show-raw`, because annotations render in the (often public) PR UI and logs.

### Example invocation

```bash
leakwatch scan fs . --format github
```

### Example output

```text
::error file=config/prod.env,line=12,title=Leakwatch%3A aws-access-key-id::Potential secret detected by aws-access-key-id (critical): AKIA****K7NP
```

This format is normally driven by the [GitHub Action](#/ci-cd/github-action) (`format: github`) rather than invoked by hand.

## Common output flags

| Flag | Short | Description |
|---|---|---|
| `--format` | `-f` | Output format: `json`, `sarif`, `csv`, `table`, `github` (default `json`) |
| `--output` | `-o` | Write to file instead of stdout |
| `--show-raw` | | Include unredacted secret value in output |
| `--min-severity` | | Drop findings below this severity level |
| `--only-verified` | | Keep only `verified_active` findings |
| `--remediation` | | Enrich findings with provider remediation guidance |

## See also

- [Remediation Guidance](#/output/remediation)
- [GitHub Action](#/ci-cd/github-action)
- [How Verification Works](#/verification/how-verification-works)

---
title: "Ignoring Findings"
description: "Suppress false positives with .leakwatchignore files, inline ignore markers, and built-in binary and lock-file skips."
---

# Ignoring Findings

No scanner has zero false positives. Leakwatch gives you three layered mechanisms to suppress the noise: a `.leakwatchignore` file for path-based exclusions, inline markers for line-level suppression, and a set of always-on built-in skips for binary files and common lock files.

## `.leakwatchignore` file

Create a `.leakwatchignore` file in your repository root (or in the current directory) to exclude paths from the scan results. It uses a gitignore-style syntax:

- Lines starting with `#` are comments.
- Blank lines are skipped.
- A `!` prefix **negates** a pattern, re-including a path that a previous pattern would have excluded.
- The **last matching pattern wins** — order matters.

### Loading order

Leakwatch loads the **first** `.leakwatchignore` it finds, checking the scan root first, then the current working directory as a fallback. Only one file is ever used per scan — if a `.leakwatchignore` exists at the scan root, the current-directory file (if any) is never opened, let alone merged. There is no cross-file precedence or merging: place your rules in a single `.leakwatchignore` at the scan root for predictable behavior.

### Glob syntax

Three pattern styles are supported:

| Style | Description | Example |
|---|---|---|
| Standard glob | `filepath.Match`-style, matched against both the full path and the base filename | `*.pem` |
| Double-star `**` | Spans zero or more path segments | `test/fixtures/**` |
| Trailing slash `dir/` | Matches every file inside the named directory at any depth | `snapshots/` |

### Example `.leakwatchignore`

```text
# Ignore all test fixture files
test/fixtures/**

# Ignore known placeholder keys in documentation
docs/examples/

# Ignore files with a specific extension anywhere in the tree
*.pem.example

# Re-include a specific file excluded by the rule above
!docs/examples/real-config-sample.yaml
```

:::note
`.leakwatchignore` filtering is applied **after** the scan completes, based on the file path of each finding. It does not prevent files from being read — it suppresses the findings they produce. To skip files before they are read at all, use `filter.exclude-paths` in the config file or `--exclude` on `scan fs`.
:::

## Inline ignore markers

Place a marker directly on any source line to suppress detectors for that specific line. The marker can appear anywhere on the line — typically inside a comment — and is applied by the engine **before** verification, so an ignored line never triggers a network call.

### Suppress all detectors on a line

```python
# Payment processing configuration
STRIPE_KEY = "sk_test_XXXXXXXXXXXXXXXXXXXX"  # leakwatch:ignore
```

### Suppress a specific detector on a line

Use `leakwatch:ignore:<detector-id>` to suppress only one detector while leaving others active:

```go
// This token is intentionally a placeholder for documentation
exampleToken := "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // leakwatch:ignore:github-token
```

```yaml
# CI environment variable set by the platform — not a real secret
api_key: "${CI_API_KEY_PLACEHOLDER}"  # leakwatch:ignore:generic-api-key
```

:::tip
Prefer the detector-specific form (`leakwatch:ignore:<detector-id>`) over the generic one whenever possible. It documents which detector you are suppressing and keeps all other detectors active on that line.
:::

## Built-in skips (always applied)

Leakwatch unconditionally skips the following before running any detector:

**Binary file extensions** — files with extensions such as `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.png`, `.jpg`, `.gif`, `.mp4`, `.zip`, `.tar`, `.gz`, `.pdf`, `.woff`, `.ttf`, and others are never scanned.

**Binary content detection** — any file whose first 8 KB contains a null byte is treated as binary and skipped, regardless of extension.

**Common lock files** — the following filenames are always skipped because they contain hashes and checksums that produce high rates of false positives:

| File |
|---|
| `package-lock.json` |
| `yarn.lock` |
| `pnpm-lock.yaml` |
| `composer.lock` |
| `Gemfile.lock` |
| `Cargo.lock` |
| `poetry.lock` |
| `go.sum` |
| `Pipfile.lock` |

These built-in skips cannot be disabled. They are separate from the `filter.exclude-paths` setting and run before any config-based filtering.

## Path-based exclusion before scanning

To exclude paths before they are even read by the scan engine, use `filter.exclude-paths` in your config file:

```yaml
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "third-party/"
```

This setting applies to **all scan sources** (filesystem, Git history, container images, cloud storage, Slack). On every `scan` subcommand that scans paths (`fs`, `git`, `image`, `s3`, `gcs`, `repos` — all except `slack`, which excludes by `--exclude-channels` instead) you can also pass `--exclude <pattern>` on the command line, repeatable, which is combined with (not a replacement for) `filter.exclude-paths`.

To silence a noisy detector for a single run without editing the config file, pass `--exclude-detectors <id>[,<id>...]` (repeatable) on any scan subcommand — see [Detector Catalog](#/detectors/detector-catalog).

See [Configuration File](#/configuration/config-file) for the full config schema and [Severity & Filtering](#/configuration/severity-and-filtering) for detector-level and severity-level filtering.

## See also

- [Configuration File](#/configuration/config-file)
- [Severity & Filtering](#/configuration/severity-and-filtering)

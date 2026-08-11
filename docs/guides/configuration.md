# Leakwatch - Configuration Guide

> **Document Version:** 1.1
> **Date:** 2026-08-11
> **Status:** Approved

---

> **Documentation role:** Supplemental configuration deep dive. The [configuration user manual](../user-manuals/en/configuration/config-file.md) is authoritative for current keys, defaults, and precedence.

## 1. Overview

Leakwatch offers a flexible configuration system. Configuration values can be read from multiple sources and are merged by overriding each other.

### 1.1 Configuration Hierarchy

Configuration values are applied in the following order of priority. A higher tier overrides a lower tier:

```mermaid
flowchart TD
    A["1. CLI Flags\n(highest priority)"] --> B
    B["2. Environment Variables\n(LEAKWATCH_ prefix)"] --> C
    C["3. Project Configuration\n(.leakwatch.yaml)"] --> D
    D["4. Global Configuration\n(~/.leakwatch.yaml)"] --> E
    E["5. Default Values\n(lowest priority)"]
```

| Priority | Source | Description |
|----------|--------|-------------|
| 1 (Highest) | CLI flags | `--concurrency 4`, `--format sarif`, etc. |
| 2 | Environment variables | `LEAKWATCH_SCAN_CONCURRENCY=4` |
| 3 | Project `.leakwatch.yaml` | Configuration file in the working directory |
| 4 | Global `~/.leakwatch.yaml` | Configuration in the user's home directory |
| 5 (Lowest) | Defaults | Default values defined in code |

**Example:** The `--concurrency 4` flag overrides the `scan.concurrency: 8` value in the `.leakwatch.yaml` file.

---

## 2. Configuration File (.leakwatch.yaml)

The easiest way to create a configuration file is with the `leakwatch init` command:

```bash
# Generate .leakwatch.yaml with recommended defaults in the current directory
leakwatch init
```

This generates a `.leakwatch.yaml` file with sensible defaults for concurrency, entropy thresholds, verification, and common exclusion patterns. You can then customize it as needed.

Leakwatch searches for the configuration file in the following order:

1. The file specified with the `--config` flag (if provided)
2. `.leakwatch.yaml` in the working directory
3. `~/.leakwatch.yaml` in the user's home directory

### 2.1 Full Schema Reference

```yaml
# .leakwatch.yaml - Full configuration example

# ── Scan Engine Settings ─────────────────────────────────────────
scan:
  # Number of worker threads to run in parallel.
  # Default: Number of CPU cores (runtime.NumCPU())
  # Valid range: 1 or more
  concurrency: 8

  # Maximum file size to scan (in bytes).
  # Files larger than this value are skipped.
  # Default: 10485760 (10 MB)
  # Valid range: 1 or more
  max-file-size: 10485760

# ── Detection Settings ────────────────────────────────────────────
detection:
  entropy:
    # Enable or disable Shannon entropy analysis.
    # Entropy helps detect text with high randomness (potential secrets).
    # Default: true
    enabled: true

    # Shannon entropy threshold (float64, 0.0–8.0). Default: 4.0
    #
    # The engine computes and attaches entropy scores to every finding. The
    # threshold gates only built-in heuristic detectors that explicitly opt in
    # (currently `generic-api-key`); structural provider detectors are never
    # suppressed by this setting. Custom rules apply their own per-rule entropy.
    threshold: 4.0

# ── Verification Settings ─────────────────────────────────────────
verification:
  # Enable or disable secret verification.
  # Verification checks whether discovered secrets are still active
  # by querying the APIs of the relevant services.
  # Default: true
  enabled: true

  # Maximum timeout for one finding's verification operation, including any
  # bounded provider-region fallback requests.
  # Go duration format: "10s", "30s", "1m"
  # Default: 10s
  timeout: 10s

  # Number of verification worker threads to run concurrently.
  # Default: 4
  concurrency: 4

  # Maximum verification API requests per second (token-bucket rate limiter).
  # Must be positive when verification is enabled.
  # Default: 10.0
  rate-limit: 10.0

# ── Filter Settings ────────────────────────────────────────────
filter:
  # File/directory patterns to exclude from scanning.
  # Glob syntax is supported (including **).
  # These patterns are evaluated together with the .leakwatchignore file.
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.lock"
    - "**/*.min.js"
    - ".git/**"

  # Detector IDs to disable.
  # If a specific detector produces too many false positives,
  # you can disable it here.
  exclude-detectors:
    - "generic-api-key"

# ── Output Settings ─────────────────────────────────────────────
output:
  # Output format.
  # Valid values: json, sarif, csv, table, github
  # Default: json
  format: json

  # Output file path.
  # If left empty, results are written to standard output (stdout).
  # Default: "" (stdout)
  file: ""

  # Include unmasked secret content in the output.
  # WARNING: Only use in secure environments.
  # Default: false
  show-raw: false

  # Minimum severity level to report.
  # Valid values: low, medium, high, critical
  # Default: low (all findings are reported)
  severity-threshold: low

# ── Custom Rules ──────────────────────────────────────────────
custom-rules:
  # Leakwatch ships with 65 detectors (61 packages). Use YAML custom rules
  # to detect secrets not covered by built-in detectors.
  # Each rule can contain the following fields:
  - id: "internal-api-key"
    description: "Internal API Key"
    # Regex pattern to capture the secret.
    # Using a capture group is recommended.
    regex: "INTERNAL_KEY_[A-Za-z0-9]{32}"
    # Keywords for Aho-Corasick pre-filtering.
    # The regex is not executed unless these keywords are found in the file (performance).
    keywords:
      - "INTERNAL_KEY_"
    # Severity level: low, medium, high, critical
    severity: high
    # Minimum entropy threshold for this rule (float64, 0.0–8.0).
    # Matches below this value are skipped. Set to 0 to disable entropy filtering.
    entropy: 3.5
```

### 2.2 Field Details

#### `scan` -- Scan Engine

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `concurrency` | int | CPU count | Worker pool size. Higher values use more memory |
| `max-file-size` | int64 | `10485760` | In bytes. Used to skip large binary files |

#### `detection.entropy` -- Entropy Analysis

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable entropy analysis |
| `threshold` | float64 | `4.0` | Entropy threshold (0.0–8.0). Gates opt-in heuristic detectors (currently `generic-api-key`); structural detectors are unaffected |

**What is entropy?** Shannon entropy measures the degree of randomness in a text. Secrets typically have high entropy (4.0+) because they consist of random characters. Normal code has lower entropy.

```mermaid
flowchart LR
    subgraph Low["Low Entropy (< 3.5)"]
        D1["password123"]
        D2["admin"]
    end
    subgraph Medium["Medium Entropy (3.5 - 4.5)"]
        O1["mySecretKey2026"]
    end
    subgraph High["High Entropy (> 4.5)"]
        Y1["aB3$kL9#mN2@pQ7"]
        Y2["AKIAIOSFODNN7EXAMPLE"]
    end
```

#### `verification` -- Secret Verification

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable verification |
| `timeout` | duration | `10s` | Timeout for one finding's complete verification operation, including bounded provider-region fallback |
| `concurrency` | int | `4` | Number of parallel verifications |
| `rate-limit` | float64 | `10.0` | Max verification API requests per second (must be positive when enabled) |

#### `filter` -- Filtering

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `exclude-paths` | []string | `[]` | Glob patterns to exclude |
| `exclude-detectors` | []string | `[]` | Detector IDs to disable |

#### `output` -- Output

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `format` | string | `json` | `json`, `sarif`, `csv`, `table`, `github` |
| `file` | string | `""` | Output file (empty = stdout) |
| `show-raw` | bool | `false` | Show secret content without masking |
| `severity-threshold` | string | `low` | Minimum reporting level |

#### `custom-rules` -- Custom Rules

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier for the rule |
| `description` | string | No | Human-readable description (recommended) |
| `regex` | string | Yes | Capture regex pattern (max 4096 characters) |
| `keywords` | []string | No | Aho-Corasick pre-filter keywords. Recommended for performance: with no keywords the regex runs against every scanned file |
| `severity` | string | No | `low`, `medium`, `high`, `critical` (default: `medium`) |
| `entropy` | float64 | No | Minimum entropy threshold for this rule (0.0–8.0). Matches below this value are skipped. Set to `0` to disable (default: `0`) |

#### `scan slack` -- Slack Workspace Scanning

Slack scanning is configured entirely via CLI flags and environment variables. There is no `slack:` key in `.leakwatch.yaml`; YAML support for Slack options is planned for a future release.

Use CLI flags directly when running `scan slack`:

```bash
# Provide the token via the environment variable (recommended — avoids storing it in config)
export LEAKWATCH_SLACK_TOKEN=xoxb-your-token-here

leakwatch scan slack \
  --channels "engineering,devops" \
  --exclude-channels "random" \
  --since "2026-01-01" \
  --rate-limit 0.8 \
  --min-severity medium
```

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | `""` | Slack Bot token (`xoxb-...`). Prefer `LEAKWATCH_SLACK_TOKEN` env var |
| `--channels` | all | Comma-separated channel names to scan |
| `--exclude-channels` | none | Comma-separated channel names to skip |
| `--since` | none | Scan messages posted after this date (`YYYY-MM-DD`) |
| `--include-dms` | `false` | Scan direct messages (requires `im:history` / `mpim:history` scopes) |
| `--include-files` | `false` | Download and scan bounded text-like attachments; requires Slack `files:read` |
| `--rate-limit` | `1/60` (~`0.0167`) | Maximum Slack API requests per second; raise only for a Marketplace/internal app with a higher published tier |

> **Security note:** Always provide the Slack token via the `LEAKWATCH_SLACK_TOKEN` environment variable rather than the `--token` flag in automated environments, to avoid token exposure in process listings or CI logs.

---

## 3. Environment Variables

All configuration values can be defined as environment variables with the `LEAKWATCH_` prefix. Use underscores (`_`) to indicate nested structure.

### 3.1 Mapping Rules

The YAML path is converted to an environment variable as follows:

```
YAML: scan.concurrency       -> LEAKWATCH_SCAN_CONCURRENCY
YAML: scan.max-file-size     -> LEAKWATCH_SCAN_MAX_FILE_SIZE
YAML: detection.entropy.enabled -> LEAKWATCH_DETECTION_ENTROPY_ENABLED
YAML: output.format          -> LEAKWATCH_OUTPUT_FORMAT
YAML: output.show-raw        -> LEAKWATCH_OUTPUT_SHOW_RAW
```

### 3.2 Usage Examples

```bash
# One-time configuration
LEAKWATCH_SCAN_CONCURRENCY=4 leakwatch scan fs .

# Using export in CI/CD environments
export LEAKWATCH_OUTPUT_FORMAT=sarif
export LEAKWATCH_OUTPUT_FILE=results.sarif
export LEAKWATCH_SCAN_CONCURRENCY=2
leakwatch scan git .

# Disabling verification via environment variable
export LEAKWATCH_VERIFICATION_ENABLED=false
leakwatch scan fs .
```

### 3.3 Priority Example

```bash
# In .leakwatch.yaml: scan.concurrency: 8
# The environment variable overrides this value:
LEAKWATCH_SCAN_CONCURRENCY=4 leakwatch scan fs .
# Result: concurrency = 4

# The CLI flag overrides both:
LEAKWATCH_SCAN_CONCURRENCY=4 leakwatch scan fs . --concurrency 2
# Result: concurrency = 2
```

---

## 4. Example Configuration Files

### 4.1 Minimal Configuration

The simplest configuration sufficient for most projects:

```yaml
# .leakwatch.yaml - Minimal
scan:
  concurrency: 4

filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
```

### 4.2 Full Configuration

A configuration where all options are explicitly specified:

```yaml
# .leakwatch.yaml - Full configuration
scan:
  concurrency: 8
  max-file-size: 10485760

detection:
  entropy:
    enabled: true
    threshold: 4.0

verification:
  enabled: true
  timeout: 10s
  concurrency: 4
  rate-limit: 10.0

filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.lock"
    - "**/*.min.js"
    - "**/*.min.css"
    - "**/*.map"
    - ".git/**"
    - "dist/**"
    - "build/**"
    - "**/*.png"
    - "**/*.jpg"
    - "**/*.gif"
    - "**/*.woff2"
  exclude-detectors: []

output:
  format: json
  file: ""
  show-raw: false
  severity-threshold: low
```

### 4.3 CI/CD Configuration

Recommended configuration for continuous integration environments:

```yaml
# .leakwatch.yaml - CI/CD
scan:
  concurrency: 2          # To conserve CI runner resources
  max-file-size: 5242880  # 5 MB (faster scanning)

detection:
  entropy:
    enabled: true
    threshold: 4.2         # Slightly more selective (fewer false positives)

verification:
  enabled: true
  timeout: 15s             # Slightly longer for network latency
  concurrency: 2

filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.lock"
    - "**/*_test.go"       # Exclude test files (optional)
    - "testdata/**"
    - "fixtures/**"

output:
  format: sarif             # Compatible with GitHub Code Scanning
  file: leakwatch-results.sarif
  show-raw: false           # NEVER show raw secrets in CI logs
  severity-threshold: medium # Skip low severity findings
```

### 4.4 Development Environment Configuration

A configuration for use during local development:

```yaml
# .leakwatch.yaml - Development
scan:
  concurrency: 4

detection:
  entropy:
    enabled: true
    threshold: 3.8         # More inclusive (more potential findings)

verification:
  enabled: true
  timeout: 10s

filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"

output:
  format: table            # Terminal-friendly output
  show-raw: false
  severity-threshold: low  # Show all findings

custom-rules:
  - id: "internal-secret"
    description: "Internal company API key"
    regex: "MYCOMPANY_SECRET_[A-Za-z0-9]{24,}"
    keywords:
      - "MYCOMPANY_SECRET_"
    severity: critical
    entropy: 0
```

---

## 5. .leakwatchignore File

The `.leakwatchignore` file is used to exclude specific files and directories from scanning. It supports syntax similar to `.gitignore`.

### 5.1 File Location

The `.leakwatchignore` file should be placed in the scan root directory. Leakwatch searches for it using the following fallback order:

1. **Scan root directory** -- the directory being scanned (e.g., the path passed to `scan fs`)
2. **Current working directory (CWD)** -- if `.leakwatchignore` is not found in the scan root, Leakwatch falls back to the directory where the command was invoked

This fallback is useful when you run a scan against a directory that differs from your working directory. For example, if you keep a shared `.leakwatchignore` in your project root but scan a subdirectory:

```bash
# CWD is /home/user/project (where .leakwatchignore lives)
# Scanning a subdirectory that has no .leakwatchignore of its own
leakwatch scan fs /home/user/project/services/api
# -> .leakwatchignore is loaded from /home/user/project/
```

```
project/
├── .leakwatchignore    # Preferred location (scan root)
├── .leakwatch.yaml
├── src/
│   └── ...
└── ...
```

### 5.2 Syntax

| Pattern | Description | Example |
|---------|-------------|---------|
| `file.txt` | A specific file | `config/secrets.example.yaml` |
| `*.ext` | Match by extension | `*.pem` |
| `directory/` | A directory and its subdirectories | `testdata/` |
| `**/pattern` | Match at any depth | `**/fixtures/**` |
| `!pattern` | Negate a previous rule (negation) | `!important.pem` |
| `# comment` | Comment line | `# Test data` |

### 5.3 Processing Rules

- Empty lines are skipped
- Lines starting with `#` are treated as comments
- Patterns are evaluated in order; **the last matching pattern takes effect**
- The `!` prefix negates a previous ignore rule (re-includes the file)
- The `**` pattern matches zero or more directory levels

### 5.4 Example .leakwatchignore

```gitignore
# ── Test and Fixture Files ──────────────────────────────────
# Fake secrets intentionally placed in test data
testdata/**
**/fixtures/**
**/*_test.go

# ── Third-Party Code ───────────────────────────────────────
vendor/**
node_modules/**
third_party/**

# ── Build Outputs ───────────────────────────────────────────
dist/**
build/**
out/**
*.min.js
*.min.css

# ── Binary and Media Files ──────────────────────────────────
*.png
*.jpg
*.jpeg
*.gif
*.ico
*.woff
*.woff2
*.ttf
*.eot
*.pdf
*.zip
*.tar.gz

# ── Lock Files ──────────────────────────────────────────────
package-lock.json
yarn.lock
go.sum
Gemfile.lock
poetry.lock

# ── Example / Template Files ────────────────────────────────
*.example
*.sample
*.template

# ── Special Exceptions ──────────────────────────────────────
# The following file is important, do not exclude from scanning
!config/production.yaml
```

### 5.5 Difference Between .leakwatchignore and filter.exclude-paths

| Feature | `.leakwatchignore` | `filter.exclude-paths` |
|---------|--------------------|-----------------------|
| Location | Project root directory | Inside `.leakwatch.yaml` |
| Negation (`!`) support | Yes | No |
| Comment support | Yes (`#`) | No |
| Priority | Applied after scanning | Applied before scanning |
| Use case | Project-specific exceptions | General filtering rules |

> **Note:** `filter.exclude-paths` patterns are applied before files are read (more performant). `.leakwatchignore` filters findings. Both can be used together.

---

## 6. Inline Ignoring

Inline ignore comments can be used to exclude specific lines from scanning within source code.

### 6.1 Ignoring All Detectors

To ignore all findings on a line:

```python
# Example Python file
API_KEY = "test_key_not_real_1234567890"  # leakwatch:ignore
```

```go
// Example Go file
const testToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // leakwatch:ignore
```

```yaml
# Example YAML file
api_key: "AKIAIOSFODNN7EXAMPLE"  # leakwatch:ignore
```

### 6.2 Ignoring a Specific Detector

To ignore only a specific detector's findings, specify the detector ID:

```python
# Ignore only the AWS Access Key detector
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # leakwatch:ignore:aws-access-key-id

# The Generic API Key detector will still scan this line
```

```go
// To ignore multiple detectors, specify each with a separate comment
const slackToken = "xoxb-example-token" // leakwatch:ignore:slack-token
```

### 6.3 Inline Ignore Rules

- The comment must be on the same line that the finding reports.
- For a multi-line secret (e.g. a private key block), the finding reports the **first line of the match**, so place the marker there — typically the `-----BEGIN ...-----` header line.
- `# leakwatch:ignore` ignores all detectors
- `# leakwatch:ignore:<detector-id>` ignores only the specified detector
- The marker only suppresses the finding on its own line. If the same secret appears again elsewhere in the file without a marker, that occurrence is still reported.
- The comment format varies by language (`#`, `//`, `/* */`, etc.)
- Ignore comments work independently of `.leakwatchignore`

### 6.4 When Should Inline Ignoring Be Used?

| Situation | Recommended Method |
|-----------|--------------------|
| Fake secret in a test file | Exclude the entire file with `.leakwatchignore` |
| False positive on a single line | `# leakwatch:ignore` |
| Excluding an entire directory | `.leakwatchignore` or `filter.exclude-paths` |
| A specific detector produces too many false positives | `filter.exclude-detectors` (persistent, in `.leakwatch.yaml`) or `--exclude-detectors` (one-off, e.g. `--exclude-detectors aws-access-key-id,generic-api-key`) |
| Fake secret in examples/documentation | `# leakwatch:ignore` |

---

## 7. Configuration Validation

Leakwatch automatically validates the configuration file when loading it. Invalid values are reported with error messages:

| Validation | Rule | Error Message |
|------------|------|---------------|
| `concurrency` | >= 1 | `invalid concurrency value: N` |
| `max-file-size` | >= 1 | `invalid max-file-size value: N` |
| `output.format` | `json`, `sarif`, `csv`, `table`, `github` | `unsupported output format: X` |
| `entropy.threshold` | 0.0 - 8.0 | `invalid entropy threshold: X (must be 0-8)` |

A **malformed `.leakwatch.yaml`** (invalid YAML syntax, or an explicit `--config` path that cannot be read) is a **fatal error** (exit code `2`) rather than a warning — detection scope can never silently diverge from what you configured. A simply-absent config file on the search path is not an error; Leakwatch falls back to defaults.

```bash
# Testing configuration in debug mode
leakwatch scan fs . --log-level debug 2>&1 | head -5
```

---

## 8. Quick Reference

### 8.1 Default Values Table

| Configuration Path | Default Value |
|--------------------|---------------|
| `scan.concurrency` | Number of CPU cores |
| `scan.max-file-size` | `10485760` (10 MB) |
| `detection.entropy.enabled` | `true` |
| `detection.entropy.threshold` | `4.0` |
| `verification.enabled` | `true` |
| `verification.timeout` | `10s` |
| `verification.concurrency` | `4` |
| `verification.rate-limit` | `10.0` |
| `output.format` | `json` |
| `output.file` | `""` (stdout) |
| `output.show-raw` | `false` |

### 8.2 Environment Variables Quick Reference

| Environment Variable | Equivalent |
|----------------------|------------|
| `LEAKWATCH_SCAN_CONCURRENCY` | `scan.concurrency` |
| `LEAKWATCH_SCAN_MAX_FILE_SIZE` | `scan.max-file-size` |
| `LEAKWATCH_DETECTION_ENTROPY_ENABLED` | `detection.entropy.enabled` |
| `LEAKWATCH_DETECTION_ENTROPY_THRESHOLD` | `detection.entropy.threshold` |
| `LEAKWATCH_VERIFICATION_ENABLED` | `verification.enabled` |
| `LEAKWATCH_VERIFICATION_TIMEOUT` | `verification.timeout` |
| `LEAKWATCH_OUTPUT_FORMAT` | `output.format` |
| `LEAKWATCH_OUTPUT_FILE` | `output.file` |
| `LEAKWATCH_OUTPUT_SHOW_RAW` | `output.show-raw` |

---

## 9. Related Documents

| Topic | Document |
|-------|----------|
| Quick start | [Getting Started Guide](./getting-started.md) |
| Development standards | [Development Standards](../standards/04-DEVELOPMENT-STANDARDS.md) |
| Architecture design | [Architecture Document](../architecture/03-ARCHITECTURE.md) |
| ADR: CLI framework (Cobra + Viper) | [ADR-0002](../decisions/ADR-0002-cli-frame.md) |
| ADR: Pattern matching | [ADR-0005](../decisions/ADR-0005-pattern-matching.md) |
| ADR: Entropy gating | [ADR-0010](../decisions/ADR-0010-entropy-gating-policy.md) |

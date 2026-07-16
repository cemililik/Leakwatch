# Leakwatch - CI/CD Integration Guide

> **Document Version:** 1.0
> **Date:** 2026-03-24
> **Status:** Approved

---

## Table of Contents

1. [Why Secret Scanning in CI/CD?](#1-why-secret-scanning-in-cicd)
2. [GitHub Actions Integration](#2-github-actions-integration)
3. [GitLab CI Integration](#3-gitlab-ci-integration)
4. [Jenkins Integration](#4-jenkins-integration)
5. [Pre-commit Hook](#5-pre-commit-hook)
6. [Docker in CI/CD](#6-docker-in-cicd)
7. [Failure Strategies](#7-failure-strategies)
8. [Best Practices](#8-best-practices)

---

## 1. Why Secret Scanning in CI/CD?

When secrets (API keys, passwords, certificates) are accidentally committed to a codebase, serious security risks arise. Since Git history is permanent, once a secret is committed, `git revert` or file deletion is not enough -- the secret remains in the Git history.

Key reasons for performing secret scanning in CI/CD pipelines:

- **Early detection:** Secrets are caught before reaching production
- **Automatic enforcement:** Does not depend on developers remembering
- **Continuous protection:** Every PR and every commit is automatically scanned
- **Compliance:** Standards like SOC 2 and ISO 27001 require automated secret scanning

```mermaid
flowchart LR
    subgraph Dev["Developer Environment"]
        A[Write Code] --> B[git commit]
    end

    subgraph CI["CI/CD Pipeline"]
        C[Pre-commit Hook] --> D[PR Scan]
        D --> E[Full History Scan]
    end

    subgraph Outcome["Result"]
        F[Success: Merge]
        G[Failure: Block]
    end

    B --> C
    E -->|Clean| F
    E -->|Secret Found| G
```

---

## 2. GitHub Actions Integration

### 2.1 Leakwatch GitHub Action

Leakwatch provides a ready-to-use GitHub Action (root `action.yml`, published on the Marketplace). The parameters supported by the Action:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scan-type` | `fs` | What to scan: `fs` (filesystem), `git` (repository history), or `image` (container image) |
| `path` | `.` | Path to scan (for `fs`/`git`) or image reference (for `image`) |
| `format` | `sarif` | Output format: `sarif`, `json`, `csv`, `table`, or `github` (inline pull-request annotations) |
| `output` | `` (empty) | Write formatted output to this file (relative to `working-directory`). Ignored for `format: github`. When empty and `format: sarif`, defaults to `results.sarif` |
| `only-verified` | `false` | Report only findings confirmed active by live verification. Has no effect when `no-verify: true` (the default) — set `no-verify: false` to enable verification first |
| `no-verify` | `true` | Disable live verification (no outbound calls to provider APIs). Recommended in CI |
| `min-severity` | `low` | Minimum severity level to report: `low`, `medium`, `high`, `critical` |
| `remediation` | `false` | Include remediation guidance (rotation steps, doc links) in the output |
| `config` | `` (empty) | Path to a `.leakwatch.yaml` configuration file |
| `scan-diff` | `auto` | For `git` scans, scan only commits new to the event instead of full history. `auto` enables this on `pull_request`/`push` events, `true` forces it, `false` always scans full history. Requires a checkout with `fetch-depth: 0` |
| `extra-args` | `` (empty) | Additional raw arguments appended to the `leakwatch scan` command (space-separated) |
| `working-directory` | `.` | Directory to run the scan from |
| `sarif-upload` | `false` | Upload SARIF results to GitHub Code Scanning. Requires `format: sarif` and `permissions: security-events: write` |
| `fail-on-findings` | `true` | Fail the workflow step when Leakwatch reports findings (exit code 1). When `false`, a `::warning::` annotation is emitted instead so the scan does not block the pipeline. Hard errors (exit code >= 2) always fail the step regardless of this setting |
| `version` | `latest` | Leakwatch version to install: `latest` or a release tag such as `v1.6.0` |
| `release-repo` | `HodeTech/Leakwatch` | GitHub repository (`owner/name`) to download the release binary from. Override only for forks or self-hosted mirrors |

**Outputs:**

| Output | Description |
|--------|-------------|
| `findings-count` | Whether secrets were reported: `1` if any finding was reported, else `0` (mirrors the `leakwatch` exit code; not a raw count of findings) |
| `sarif-file` | Path to the SARIF output file relative to the repository root (set when `format: sarif`) |

### 2.2 Basic Usage

The simplest integration -- filesystem scan on every push:

```yaml
# .github/workflows/leakwatch.yml
name: Secret Scanning

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Required for full Git history

      - name: Leakwatch Scan
        uses: HodeTech/Leakwatch@v1
        with:
          scan-type: fs
          no-verify: false      # verification ON (required for only-verified)
          only-verified: true
```

### 2.3 SARIF with GitHub Code Scanning Integration

GitHub Code Scanning displays SARIF-formatted results directly in the Security tab. This way, found secrets are shown alongside the relevant code line.

```yaml
# .github/workflows/leakwatch-sarif.yml
name: Secret Scanning with Code Scanning

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Leakwatch Scan
        uses: HodeTech/Leakwatch@v1
        with:
          scan-type: git
          format: sarif
          sarif-upload: true
          min-severity: medium
```

```mermaid
sequenceDiagram
    participant GH as GitHub Actions
    participant LW as Leakwatch
    participant CS as Code Scanning

    GH->>LW: leakwatch scan git . --format sarif
    LW-->>GH: results.sarif
    GH->>CS: Upload SARIF
    CS-->>GH: View in Security tab
```

### 2.4 Pull Request Scanning (Changed Files Only)

Scanning the entire history in PR scans wastes unnecessary time. With the `--since-commit` parameter, you can scan only the changes in the PR:

```yaml
# .github/workflows/leakwatch-pr.yml
name: PR Secret Scanning

on:
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  leakwatch-pr:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      # Find the PR base commit
      - name: Determine base commit
        id: base
        run: |
          BASE_SHA=$(git merge-base origin/${{ github.base_ref }} HEAD)
          echo "sha=$BASE_SHA" >> "$GITHUB_OUTPUT"

      - name: Leakwatch PR scan
        run: |
          go install github.com/HodeTech/leakwatch@latest
          leakwatch scan git . \
            --since-commit ${{ steps.base.outputs.sha }} \
            --format sarif \
            --output results.sarif \
            --min-severity medium

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: leakwatch
```

### 2.5 Full History Scanning

Scanning the entire Git history on a weekly or monthly basis is important for catching secrets that were previously missed:

```yaml
# .github/workflows/leakwatch-full.yml
name: Full History Secret Scanning

on:
  schedule:
    # Every Monday at 03:00 UTC
    - cron: '0 3 * * 1'
  workflow_dispatch:  # Manual trigger

permissions:
  security-events: write
  contents: read

jobs:
  full-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Checkout (full history)
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Full history scan
        uses: HodeTech/Leakwatch@v1
        with:
          scan-type: git
          format: sarif
          sarif-upload: true
          min-severity: low

      - name: Save results as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: leakwatch-full-scan-results
          path: results.sarif
          retention-days: 90
```

### 2.6 Comprehensive Workflow Example

The following example is a comprehensive workflow that combines PR scanning, full scanning, and Code Scanning:

```yaml
# .github/workflows/leakwatch-complete.yml
name: Leakwatch Complete Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'

permissions:
  security-events: write
  contents: read
  pull-requests: read

env:
  LEAKWATCH_VERSION: 'v1.6.0'

jobs:
  # On PRs, scan only the changed files
  pr-scan:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Determine base commit
        id: base
        run: |
          BASE_SHA=$(git merge-base origin/${{ github.base_ref }} HEAD)
          echo "sha=$BASE_SHA" >> "$GITHUB_OUTPUT"

      - name: PR scan
        run: |
          go install github.com/HodeTech/leakwatch@${{ env.LEAKWATCH_VERSION }}
          leakwatch scan git . \
            --since-commit ${{ steps.base.outputs.sha }} \
            --format sarif \
            --output results.sarif \
            --min-severity medium

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: leakwatch-pr

  # On pushes, scan the filesystem
  push-scan:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Filesystem scan
        uses: HodeTech/Leakwatch@v1
        with:
          scan-type: fs
          format: sarif
          sarif-upload: true
          min-severity: high

  # Scheduled full history scan
  scheduled-scan:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Full history scan
        uses: HodeTech/Leakwatch@v1
        with:
          scan-type: git
          format: sarif
          sarif-upload: true
          min-severity: low

      - name: Save results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: leakwatch-scheduled-${{ github.run_id }}
          path: results.sarif
          retention-days: 90
```

---

## 3. GitLab CI Integration

### 3.1 Basic GitLab CI Configuration

```yaml
# .gitlab-ci.yml
stages:
  - security

leakwatch-scan:
  stage: security
  image: golang:1.25-alpine
  before_script:
    - go install github.com/HodeTech/leakwatch@latest
  script:
    - leakwatch scan fs . --format sarif --output leakwatch-results.sarif --min-severity medium
  artifacts:
    reports:
      sast: leakwatch-results.sarif
    paths:
      - leakwatch-results.sarif
    when: always
    expire_in: 30 days
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### 3.2 Merge Request Scanning

To scan only the changed commits in merge requests:

```yaml
# .gitlab-ci.yml
stages:
  - security

leakwatch-mr-scan:
  stage: security
  image: golang:1.25-alpine
  before_script:
    - apk add --no-cache git
    - go install github.com/HodeTech/leakwatch@latest
  script:
    # Find the MR base commit
    - BASE_SHA=$(git merge-base origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME HEAD)
    - leakwatch scan git . --since-commit "$BASE_SHA" --format sarif --output leakwatch-results.sarif
  artifacts:
    reports:
      sast: leakwatch-results.sarif
    paths:
      - leakwatch-results.sarif
    when: always
    expire_in: 30 days
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'

leakwatch-full-scan:
  stage: security
  image: golang:1.25-alpine
  before_script:
    - apk add --no-cache git
    - go install github.com/HodeTech/leakwatch@latest
  script:
    - leakwatch scan git . --format sarif --output leakwatch-results.sarif --min-severity low
  artifacts:
    reports:
      sast: leakwatch-results.sarif
    paths:
      - leakwatch-results.sarif
    when: always
    expire_in: 90 days
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
      when: always
  # For a weekly scheduled pipeline:
  # create a weekly schedule under GitLab > CI/CD > Schedules
```

### 3.3 GitLab CI with Docker Image

Using the Docker image without requiring Go installation:

```yaml
leakwatch-docker-scan:
  stage: security
  image:
    name: ghcr.io/hodetech/leakwatch:latest
    entrypoint: [""]
  script:
    - leakwatch scan fs /builds/$CI_PROJECT_PATH --format sarif --output leakwatch-results.sarif
  artifacts:
    reports:
      sast: leakwatch-results.sarif
    paths:
      - leakwatch-results.sarif
    when: always
```

---

## 4. Jenkins Integration

### 4.1 Declarative Jenkinsfile

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        LEAKWATCH_VERSION = 'latest'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Leakwatch') {
            steps {
                sh '''
                    go install github.com/HodeTech/leakwatch@${LEAKWATCH_VERSION}
                '''
            }
        }

        stage('Secret Scan') {
            steps {
                sh '''
                    leakwatch scan fs . \
                        --format sarif \
                        --output leakwatch-results.sarif \
                        --min-severity medium
                '''
            }
            post {
                always {
                    // Archive the SARIF results
                    archiveArtifacts artifacts: 'leakwatch-results.sarif', allowEmptyArchive: true
                }
                failure {
                    echo 'Leakwatch detected secrets! Review the results.'
                }
            }
        }
    }

    post {
        always {
            // Also produce a JSON report
            sh '''
                leakwatch scan fs . \
                    --format json \
                    --output leakwatch-results.json \
                    --min-severity medium || true
            '''
            archiveArtifacts artifacts: 'leakwatch-results.json', allowEmptyArchive: true
        }
    }
}
```

### 4.2 Jenkinsfile with Docker Agent

```groovy
// Jenkinsfile (Docker agent)
pipeline {
    agent {
        docker {
            image 'ghcr.io/hodetech/leakwatch:latest'
            args '-v ${WORKSPACE}:/scan'
        }
    }

    stages {
        stage('Secret Scan') {
            steps {
                sh '''
                    leakwatch scan fs /scan \
                        --format sarif \
                        --output /scan/leakwatch-results.sarif \
                        --min-severity medium
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'leakwatch-results.sarif', allowEmptyArchive: true
        }
    }
}
```

---

## 5. Pre-commit Hook

The pre-commit hook ensures secrets are caught before being committed to the Git repository. This is the earliest point to prevent secret leaks.

### 5.1 Installation

First, install the [pre-commit](https://pre-commit.com/) framework:

```bash
# Install pre-commit
pip install pre-commit
```

Create a `.pre-commit-config.yaml` file in your project root:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/HodeTech/Leakwatch
    rev: v1.6.0
    hooks:
      - id: leakwatch
```

Activate the hook:

```bash
# Install the hook
pre-commit install

# Test against all files
pre-commit run leakwatch --all-files
```

### 5.2 How Does It Work?

The Leakwatch pre-commit hook runs the `leakwatch scan fs` command. The bundled hook sets `pass_filenames: false`, so it scans the entire working tree on each commit rather than only the staged files.

```mermaid
flowchart TD
    A[git commit] --> B[pre-commit hook triggered]
    B --> C[leakwatch scan fs]
    C --> D{Secret found?}
    D -->|No| E[Commit succeeds]
    D -->|Yes| F[Commit blocked]
    F --> G[Developer removes secret]
    G --> A
```

### 5.3 Pre-commit Validation in CI

To verify that pre-commit hooks are working correctly in the CI pipeline:

```yaml
# .github/workflows/pre-commit.yml
name: Pre-commit Validation

on: [push, pull_request]

jobs:
  pre-commit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - run: pip install pre-commit
      - run: pre-commit run --all-files
```

---

## 6. Docker in CI/CD

The Leakwatch Docker image can be used in any CI/CD environment without requiring Go installation.

### 6.1 Docker Image

The Leakwatch Docker image is published on GitHub Container Registry as `ghcr.io/hodetech/leakwatch`. The image is based on Alpine Linux and has a minimal size.

```bash
# Scan a local directory
docker run --rm -v "$(pwd):/scan" ghcr.io/hodetech/leakwatch:latest scan fs /scan

# Scan a Git repository
docker run --rm -v "$(pwd):/scan" ghcr.io/hodetech/leakwatch:latest scan git /scan

# SARIF output
docker run --rm -v "$(pwd):/scan" ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan --format sarif --output /scan/results.sarif

# Show only verified active secrets
docker run --rm -v "$(pwd):/scan" ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan --only-verified
```

### 6.2 Scanning in Multi-stage Builds

You can perform secret scanning during the build stage within your own Dockerfile:

```dockerfile
# Build stage
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY . .
RUN go build -o myapp .

# Security scan stage
FROM ghcr.io/hodetech/leakwatch:latest AS security
COPY --from=builder /app /scan
RUN leakwatch scan fs /scan --min-severity high

# Runtime stage (reached only if the scan succeeded)
FROM alpine:3.20
COPY --from=builder /app/myapp /usr/local/bin/
ENTRYPOINT ["myapp"]
```

In this approach, if a secret is found, `leakwatch` returns a non-zero exit code and the Docker build fails. This prevents creating an image that contains secrets.

### 6.3 Container Image Scanning

To scan container images for secrets, provide the full registry reference. Leakwatch pulls the image directly from the registry using `go-containerregistry` — no Docker daemon or socket mount is required:

```bash
# Scan a Docker Hub image
docker run --rm ghcr.io/hodetech/leakwatch:latest scan image nginx:latest

# Scan a GHCR image
docker run --rm ghcr.io/hodetech/leakwatch:latest scan image ghcr.io/myorg/myapp:latest
```

---

## 7. Failure Strategies

It is important to control how the CI/CD pipeline behaves when secret scanning fails (when a secret is found).

### 7.1 Setting Thresholds with `--min-severity`

You can set a minimum severity level to prevent low-priority findings from blocking the pipeline:

```bash
# Fail only on high and critical findings
leakwatch scan fs . --min-severity high

# Fail only on critical findings
leakwatch scan fs . --min-severity critical
```

**Severity levels:**

| Level | Description | Example |
|-------|-------------|---------|
| `low` | Low risk, may be a false positive | Generic API key pattern |
| `medium` | Medium risk | Database connection string |
| `high` | High risk | AWS Secret Access Key |
| `critical` | Critical risk, verified active secret | Verified AWS key |

### 7.2 Reducing False Positives with `--only-verified`

Leakwatch ships with 54 verifiers (51 packages) covering 84.4% of all detector types, confirming whether discovered secrets are still active via API calls. With the `--only-verified` parameter, you can report only verified (active) secrets:

```bash
# Report only verified secrets
leakwatch scan git . --only-verified

# Use together with verification in PR scans
leakwatch scan git . --since-commit HEAD~1 --only-verified --min-severity medium
```

**Note:** With 54 verifiers (51 packages) and 84.4% coverage, `--only-verified` is effective for most secret types. However, the remaining ~16% of detectors (e.g., generic private keys) do not have verifiers, so those findings will not be reported. For full coverage, periodically run a full scan without `--only-verified`.

> **Important:** `--only-verified` has **no effect** when `--no-verify` is also set (or when `verification.enabled: false` in config), because verification is disabled and all findings remain in the `unverified` state. To use `--only-verified` meaningfully, ensure verification is enabled by omitting `--no-verify` and setting `verification.enabled: true` in your config.

### 7.3 Excluding Known Values with `.leakwatchignore`

Use the `.leakwatchignore` file for known false positives or intentional test values in the code:

```bash
# .leakwatchignore

# Test fixtures
test/fixtures/**
testdata/**

# Example configuration files
*.example
*.sample

# Specific files
docs/examples/config.yaml

# Inline ignore (within code)
# leakwatch:ignore
```

You can use inline comments to ignore specific lines within the code:

```go
// Example key for testing (not real)
var testKey = "AKIAIOSFODNN7EXAMPLE" // leakwatch:ignore
```

### 7.4 Strategy Matrix

Recommended configurations for different scenarios:

| Scenario | `--min-severity` | `--only-verified` | `.leakwatchignore` |
|----------|-------------------|--------------------|--------------------|
| PR scanning | `medium` | Yes | Yes |
| Main branch push | `high` | No | Yes |
| Scheduled full scan | `low` | No | Yes |
| Pre-commit hook | `medium` | No | Yes |
| Pre-release | `low` | No | Minimal |

---

## 8. Best Practices

### 8.1 Layered Defense

Do not rely on a single checkpoint. Perform secret scanning at multiple layers:

```mermaid
flowchart TD
    A[Developer: pre-commit hook] --> B[PR: Change scan]
    B --> C[Main: Push scan]
    C --> D[Scheduled: Full history scan]
    D --> E[Deploy: Container image scan]

    style A fill:#e1f5fe
    style B fill:#fff3e0
    style C fill:#fce4ec
    style D fill:#f3e5f5
    style E fill:#e8f5e9
```

### 8.2 Exit Codes

Interpret Leakwatch exit codes correctly in the CI/CD pipeline:

| Exit Code | Meaning | CI/CD Action |
|-----------|---------|--------------|
| `0` | No secrets found | Pipeline continues |
| `1` | Secrets found | Pipeline fails |
| `2+` | Error (configuration, IO, etc.) | Pipeline fails, error is investigated |

### 8.3 Performance Optimization

- **`fetch-depth: 0`** should only be used when Git history scanning is needed. For filesystem scanning, `fetch-depth: 1` is sufficient
- **`--since-commit`** in PR scans, scan only changed commits instead of the entire history
- **`.leakwatchignore`** to exclude large binary files, vendor directories, and test fixtures
- **`--max-file-size`** to set a file size limit for skipping large files

### 8.4 Configuration File

Centralize recurring parameters with a `.leakwatch.yaml` file in the project root:

```yaml
# .leakwatch.yaml
scan:
  concurrency: 8
  max-file-size: 10485760  # 10MB

detection:
  entropy:
    enabled: true
    threshold: 4.0

verification:
  enabled: true
  timeout: 10s

filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.lock"
    - "**/*.min.js"
    - "testdata/**"

output:
  format: json
  show-raw: false  # Never show found secrets in plain text
```

### 8.5 Privacy and Security

- **Never write the raw values of found secrets to logs** in Leakwatch output. Use the `show-raw: false` setting
- Do not store SARIF reports for extended periods; 90 days is a reasonable duration
- Use `--format sarif` or `--format json` to mask secret values in CI/CD logs (`table` format writes to the console)
- Store API access credentials needed for secret verification in the CI/CD secret manager

### 8.6 Notifications

Use CI/CD notification mechanisms to inform the team when secrets are found:

```yaml
# GitHub Actions example - Slack notification
- name: Slack Notification
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "Leakwatch detected secrets: ${{ github.repository }} (${{ github.ref_name }})"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 8.7 Scan Summary in CI Logs

Leakwatch prints a scan summary to stderr after every scan. This summary is valuable in CI/CD logs for tracking scan metadata without parsing the structured output:

```
── Scan Summary ─────────────────────────────────
  Date:            2026-04-08 14:22:00
  Source:          filesystem
  Target:          /home/runner/work/my-app/my-app
  Files scanned:   1247
  Duration:        2.34s
  Findings:        3
─────────────────────────────────────────────────
```

Because the summary is written to stderr, it appears in the CI log even when stdout is redirected to a file (e.g., `--output results.sarif`). This makes it easy to review scan metrics at a glance in GitHub Actions, GitLab CI, or Jenkins build logs without opening the artifact.

Example in a GitHub Actions workflow:

```yaml
- name: Leakwatch Scan
  run: |
    leakwatch scan fs . \
      --format sarif --output results.sarif \
      --min-severity medium
    # The scan summary is printed to stderr and visible
    # in the step log regardless of --output redirection.
```

---

## Related Documents

- [Custom Rules Guide](custom-rules.md)
- [Architecture Design](../architecture/03-ARCHITECTURE.md)
- [Development Standards](../standards/04-DEVELOPMENT-STANDARDS.md)
- [Release and Distribution Standards](../standards/02-RELEASE-STANDARDS.md)

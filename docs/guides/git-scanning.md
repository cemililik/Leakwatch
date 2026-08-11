# Leakwatch - Git Repository Scanning Guide

> **Document Version:** 1.1
> **Date:** 2026-08-11
> **Status:** Approved

---

> **Documentation role:** Supplemental Git-scanning deep dive. The [Git-history user manual](../user-manuals/en/scanning/git-history.md) is authoritative for current target and history semantics.

## 1. Overview

The `scan git` command scans the entire commit history of a Git repository to find leaked secrets. Unlike a filesystem scan, which only checks current file contents, a Git scan examines every blob across all commits -- uncovering secrets that were added and later deleted.

Leakwatch uses [go-git](https://github.com/go-git/go-git) for all Git operations. This means no external `git` binary is required, and there are no CGO dependencies.

**Key features:**

- **Full history scanning** -- examines every commit, every file version
- **Diff-based scanning** -- scan only changes since a specific commit (ideal for CI/CD)
- **Remote repository support** -- clone and scan via HTTPS or SSH
- **Blob deduplication** -- skips identical file contents across commits for better performance
- **Date and depth filtering** -- limit scan scope for faster results

---

## 2. Local Repository Scanning

### 2.1 Basic Usage

Scan a local Git repository by providing the path:

```bash
# Scan the current directory
leakwatch scan git .

# Scan a specific repository
leakwatch scan git /path/to/repo
```

### 2.2 What Gets Scanned

A full history scan iterates over every commit (ordered by committer time) and examines every file blob in each commit tree. The process includes:

1. **All commits** on the current branch (or a specified branch)
2. **All file blobs** within each commit tree
3. **Blob deduplication** -- if the same file content (identical Git blob hash) appears in multiple commits, it is scanned only once
4. **Binary file exclusion** -- binary files are automatically skipped
5. **File size limit** -- files exceeding the maximum size (default: 10 MB) are skipped

```bash
# Scan with verbose output to see commit and blob counts
leakwatch scan git . --log-level info
```

---

## 3. Remote Repository Scanning

Leakwatch can clone and scan remote repositories directly. The repository is cloned to a temporary directory and automatically cleaned up after the scan completes.

### 3.1 HTTPS

```bash
# Public repository
leakwatch scan git https://github.com/org/repo.git

# Private repository with token (via URL)
leakwatch scan git https://x-access-token:ghp_TOKEN@github.com/org/private-repo.git
```

### 3.2 SSH

```bash
# SSH with default key (~/.ssh/id_rsa or ssh-agent)
leakwatch scan git git@github.com:org/repo.git

# SSH URL format
leakwatch scan git ssh://git@github.com/org/repo.git
```

### 3.3 Authentication

For private repositories, Leakwatch supports the same authentication methods as `git clone`:

| Method | Example |
|--------|---------|
| HTTPS with token | `https://x-access-token:TOKEN@github.com/org/repo.git` |
| SSH with key agent | `git@github.com:org/repo.git` (uses ssh-agent) |
| SSH URL | `ssh://git@github.com/org/repo.git` |

> **Security note:** Leakwatch redacts credentials from URLs in all log messages. However, avoid passing tokens directly on the command line in shared environments. Use environment variables or CI/CD secret management instead.

---

## 4. Git Scan Pipeline

The following diagram illustrates how Leakwatch processes a Git repository during a full history scan:

```mermaid
flowchart TD
    A["Input: local path or remote URL"] --> B{Is remote?}
    B -->|Yes| C["Clone to temp directory\n(respects --depth, --branch)"]
    B -->|No| D["Open local repository"]
    C --> E["Iterate commits\n(ordered by committer time)"]
    D --> E
    E --> F["Extract file blobs\nfrom each commit tree"]
    F --> G{"Blob already\nseen?"}
    G -->|Yes| H["Skip (deduplicated)"]
    G -->|No| I{"Binary or\ntoo large?"}
    I -->|Yes| J["Skip"]
    I -->|No| K["Read file contents"]
    K --> L["Send chunk to\ndetection engine"]
    L --> M["Aho-Corasick\npre-filter"]
    M --> N["Regex validation"]
    N --> O["Entropy analysis"]
    O --> P["Findings with\ncommit metadata"]

    H --> F
    J --> F
```

---

## 5. Scan Limiting Flags

### 5.1 `--since` (Date Filter)

Scan only commits after a specific date. The date format is `YYYY-MM-DD`.

```bash
# Scan commits from the last 30 days
leakwatch scan git . --since 2026-02-22

# Scan commits from the start of the year
leakwatch scan git . --since 2026-01-01
```

This is useful for periodic audits where you only need to check recent activity.

### 5.2 `--depth` (Clone Depth)

Limit the number of commits fetched when cloning a remote repository. This flag only applies to remote repositories and is ignored for local ones.

```bash
# Clone only the last 50 commits
leakwatch scan git https://github.com/org/repo.git --depth 50

# Shallow clone with single commit (fastest possible scan of latest state)
leakwatch scan git https://github.com/org/repo.git --depth 1
```

### 5.3 `--branch` (Specific Branch)

Scan a specific branch instead of the default. For remote repositories, this also limits the clone to a single branch.

```bash
# Scan a feature branch
leakwatch scan git . --branch feature/payment

# Scan the production branch of a remote repository
leakwatch scan git https://github.com/org/repo.git --branch main
```

### 5.4 Flag Combinations

Flags can be combined for precise scan targeting:

```bash
# Remote repo, main branch, last 100 commits, since January
leakwatch scan git https://github.com/org/repo.git \
  --branch main \
  --depth 100 \
  --since 2026-01-01
```

---

## 6. Diff-Based Scanning with `--since-commit`

The `--since-commit` flag enables diff-based scanning, which only examines changes introduced between a specific commit and HEAD. This is the recommended mode for CI/CD pipelines.

```bash
# Scan changes since a specific commit hash
leakwatch scan git . --since-commit abc1234def5678

# Scan only the last commit
leakwatch scan git . --since-commit HEAD~1

# Scan the last 5 commits
leakwatch scan git . --since-commit HEAD~5
```

### 6.1 How Diff-Based Scanning Works

Instead of scanning every blob in every commit, diff-based scanning:

1. Resolves the `--since-commit` hash and the current HEAD
2. Iterates commits from HEAD backwards until it reaches the since-commit
3. For each commit, computes the diff against its parent
4. Scans only **added or modified files** (deleted files are skipped)
5. Applies blob deduplication across all diffs

This dramatically reduces scan time in CI/CD where you only care about newly introduced secrets.

```mermaid
flowchart LR
    subgraph Full["Full History Scan"]
        direction TB
        FA["All commits"] --> FB["All blobs in\neach commit tree"]
        FB --> FC["Deduplicated\nblob scanning"]
    end

    subgraph Diff["Diff-Based Scan (--since-commit)"]
        direction TB
        DA["Commits from\nsince-commit to HEAD"] --> DB["Only changed files\n(added/modified)"]
        DB --> DC["Deduplicated\nblob scanning"]
    end

    Full -.-|"Thorough, slower\nBest for audits"| Note1[" "]
    Diff -.-|"Fast, incremental\nBest for CI/CD"| Note2[" "]

    style Note1 fill:none,stroke:none
    style Note2 fill:none,stroke:none
```

---

## 7. Commit Metadata in Findings

When scanning Git repositories, each finding includes commit metadata in the `source` object:

```json
{
  "source": {
    "source_type": "git",
    "repository": "/path/to/repo",
    "commit": "abc1234def567890abcdef1234567890abcdef12",
    "author": "Jane Developer",
    "email": "jane@example.com",
    "date": "2026-03-20T10:30:00Z",
    "branch": "main",
    "file_path": "config/settings.py",
    "line": 42
  }
}
```

| Field | Description |
|-------|-------------|
| `commit` | Full SHA-1 hash of the commit that introduced the secret. |
| `author` | Name of the commit author. |
| `email` | Email of the commit author. |
| `date` | Author date of the commit (ISO 8601 format). |
| `branch` | Branch that was scanned. For local repos, this is the current HEAD branch unless `--branch` is specified. |
| `file_path` | Path of the file within the repository at the time of the commit. |

This metadata helps you trace exactly who introduced a secret, when it happened, and in which commit -- making remediation faster and more targeted.

---

## 8. Performance Optimization

### 8.1 Blob Deduplication

Leakwatch maintains a map of seen blob hashes during scanning. If the same file content appears in multiple commits (which is common -- most files do not change between commits), it is scanned only once. This is the single biggest performance optimization for full history scans.

The deduplication map has an upper limit of 1,000,000 entries to prevent unbounded memory growth. For extremely large repositories that exceed this limit, deduplication is disabled for the remaining blobs, and a warning is logged.

### 8.2 Depth Limiting for Remote Repositories

For remote repositories, use `--depth` to perform a shallow clone:

```bash
# Only fetch the last 100 commits (much faster than a full clone)
leakwatch scan git https://github.com/org/large-repo.git --depth 100
```

### 8.3 Date Filtering

Use `--since` to skip older commits that have already been audited:

```bash
# Only scan commits from the last quarter
leakwatch scan git . --since 2025-12-24
```

### 8.4 Large Repository Strategies

For repositories with thousands of commits and large histories:

| Strategy | Command | Benefit |
|----------|---------|---------|
| Shallow clone | `--depth 100` | Reduces clone time and commit count |
| Date filter | `--since 2026-01-01` | Skips already-audited history |
| Diff-based | `--since-commit <hash>` | Scans only new changes |
| Branch targeting | `--branch main` | Avoids scanning feature branches |
| Reduce workers | `--concurrency 2` | Lower memory usage on constrained systems |
| File size limit | `--max-file-size 5242880` | Skip files larger than 5 MB |

Recommended approach for initial audits of very large repositories:

```bash
# Step 1: Scan recent history first
leakwatch scan git . --since 2026-01-01 --format json --output recent.json

# Step 2: If needed, do a full scan with lower concurrency
leakwatch scan git . --concurrency 2 --format json --output full.json
```

---

## 9. CI/CD Integration

### 9.1 GitHub Actions

Use `--since-commit` with the base commit of a pull request to scan only the changes introduced in that PR:

```yaml
name: Secret Scanning
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history needed for --since-commit

      - name: Install Leakwatch
        run: go install github.com/HodeTech/leakwatch@latest

      - name: Scan for secrets (PR)
        if: github.event_name == 'pull_request'
        run: |
          leakwatch scan git . \
            --since-commit ${{ github.event.pull_request.base.sha }} \
            --format sarif \
            --output results.sarif

      - name: Scan for secrets (push)
        if: github.event_name == 'push'
        run: |
          leakwatch scan git . \
            --since-commit ${{ github.event.before }} \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

> **Important:** Use `fetch-depth: 0` (or a sufficient depth) in the checkout step so that Leakwatch can access the commit history needed for `--since-commit`.

### 9.2 GitLab CI

```yaml
secret-scan:
  stage: test
  image: golang:1.25-alpine
  before_script:
    - go install github.com/HodeTech/leakwatch@latest
  script:
    - |
      if [ -n "$CI_MERGE_REQUEST_DIFF_BASE_SHA" ]; then
        # Merge request: scan only changes
        leakwatch scan git . \
          --since-commit "$CI_MERGE_REQUEST_DIFF_BASE_SHA" \
          --format json \
          --output gl-secret-report.json
      else
        # Branch push: scan last commit
        leakwatch scan git . \
          --since-commit HEAD~1 \
          --format json \
          --output gl-secret-report.json
      fi
  artifacts:
    reports:
      secret_detection: gl-secret-report.json
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### 9.3 Pre-commit Hook

Add a Git pre-commit hook to catch secrets before they are committed:

Pre-commit changes are not committed yet, so scan the working tree with
`scan fs` rather than git history: a `scan git` run cannot see uncommitted
changes, and `--since-commit HEAD` would scan zero commits (the diff walk stops
as soon as it reaches the since-commit, which is HEAD itself).

```bash
#!/bin/sh
# .git/hooks/pre-commit

leakwatch scan fs . --only-verified --min-severity high
if [ $? -eq 1 ]; then
    echo "ERROR: Active secrets detected. Commit blocked."
    exit 1
fi
```

> **Tip:** This mirrors the bundled [pre-commit framework](https://pre-commit.com)
> hook in `.pre-commit-hooks.yaml`, which runs `leakwatch scan fs`. For faster
> commits, add `--no-verify` to skip the network verification step.

---

## 10. Diff-Based vs Full Scan Comparison

```mermaid
flowchart TD
    subgraph FullScan["Full History Scan"]
        FS1["leakwatch scan git ."]
        FS2["Scans ALL commits"]
        FS3["Scans ALL blobs\n(deduplicated)"]
        FS4["Complete coverage"]
        FS1 --> FS2 --> FS3 --> FS4
    end

    subgraph DiffScan["Diff-Based Scan"]
        DS1["leakwatch scan git . --since-commit SHA"]
        DS2["Scans commits\nSHA → HEAD only"]
        DS3["Scans CHANGED blobs only\n(added/modified)"]
        DS4["Incremental coverage"]
        DS1 --> DS2 --> DS3 --> DS4
    end

    FullScan --- Comparison
    DiffScan --- Comparison

    subgraph Comparison["When to Use"]
        C1["Full Scan:\n- First-time audit\n- Periodic security review\n- Onboarding new repos"]
        C2["Diff-Based Scan:\n- CI/CD pipelines\n- Pull request checks\n- Pre-commit hooks"]
    end
```

| Aspect | Full History Scan | Diff-Based Scan |
|--------|-------------------|-----------------|
| **Command** | `leakwatch scan git .` | `leakwatch scan git . --since-commit <SHA>` |
| **Scope** | All commits, all blobs | Only commits between SHA and HEAD |
| **Speed** | Slower (proportional to repo size) | Fast (proportional to change size) |
| **Coverage** | Complete -- finds secrets in any historical commit | Incremental -- only finds secrets in new changes |
| **Use case** | Security audits, onboarding | CI/CD, pull request checks |
| **Memory** | Higher (dedup map grows with repo size) | Lower (fewer blobs to track) |

---

## 11. Quick Reference

| Task | Command |
|------|---------|
| Scan local repo (full history) | `leakwatch scan git .` |
| Scan remote repo | `leakwatch scan git https://github.com/org/repo.git` |
| Scan specific branch | `leakwatch scan git . --branch main` |
| Scan since a date | `leakwatch scan git . --since 2026-01-01` |
| Scan since a commit (CI/CD) | `leakwatch scan git . --since-commit HEAD~1` |
| Shallow clone scan | `leakwatch scan git https://github.com/org/repo.git --depth 50` |
| Output as SARIF | `leakwatch scan git . --format sarif --output results.sarif` |
| Only verified critical | `leakwatch scan git . --only-verified --min-severity critical` |
| Debug mode | `leakwatch scan git . --log-level debug` |

---

## 12. Next Steps

| Topic | Document |
|-------|----------|
| Getting started with Leakwatch | [Getting Started Guide](./getting-started.md) |
| Configuration file and options | [Configuration Guide](./configuration.md) |
| VS Code integration | [VS Code Extension Guide](./vscode-extension.md) |
| Output formats and fields | [Getting Started Guide -- Understanding the Output](./getting-started.md#5-understanding-the-output) |
| Architecture overview | [Architecture Document](../architecture/03-ARCHITECTURE.md) |

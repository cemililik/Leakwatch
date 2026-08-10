---
title: "Introduction"
description: "What Leakwatch is, what it scans, and how it detects and verifies leaked secrets."
---

# Introduction

**Leakwatch** is a high-performance, open-source (MIT) security tool that **detects, verifies, and reports leaked secrets** — API keys, tokens, passwords, connection strings, and private keys — across your codebases, Git history, container images, cloud storage, and Slack workspaces.

It is written in Go, ships as a single static binary with no runtime dependencies (`CGO_ENABLED=0`), and is built to run anywhere: a developer laptop, a pre-commit hook, or a CI/CD pipeline.

## Why Leakwatch

A leaked credential in a single commit — even one later deleted — can stay reachable in Git history forever and be exploited within minutes of being pushed. Leakwatch is designed to catch those secrets early and tell you which ones are *actually dangerous*:

- **Broad detection** — 65 built-in detectors covering cloud providers, AI APIs, payment platforms, databases, messaging tools, structured configuration, and more, plus your own YAML custom rules.
- **Truthful verification capability** — 45 detector types have a direct live check, 3 need trusted or companion context, and 6 perform offline format validation. Registry count is never presented as live coverage.
- **Many sources** — scan a local filesystem, a full Git history, an OCI/Docker image, AWS S3, Google Cloud Storage, and Slack messages.
- **CI-native output** — JSON, SARIF (for GitHub Code Scanning), CSV, a colorized terminal table, and inline GitHub Actions annotations.
- **Secret-safe by design** — discovered secrets are redacted by default and are never logged, cached, or written to disk.

## What it scans

| Source | Command | What it covers |
|--------|---------|----------------|
| Filesystem | `leakwatch scan fs` | Files in a local directory tree |
| Git history | `leakwatch scan git` | Every blob across the full commit history (local or remote) |
| Container image | `leakwatch scan image` | OCI/Docker image layers, daemonless |
| AWS S3 | `leakwatch scan s3` | Objects in an S3 bucket |
| Google Cloud Storage | `leakwatch scan gcs` | Objects in a GCS bucket |
| Slack | `leakwatch scan slack` | Message text in channels and (optionally) DMs |
| Multiple repos | `leakwatch scan repos` | Several Git repositories at once |

## How detection works, briefly

Leakwatch uses a layered pipeline so it stays fast even on large inputs:

1. **Aho-Corasick keyword pre-filter** — a single multi-pattern automaton quickly decides which detectors *could* match a chunk, so most detectors never run their regex.
2. **Regex validation** — only the shortlisted detectors run their precise patterns.
3. **Entropy** — Shannon entropy is computed for display, and gates the built-in `generic-api-key` detector plus any custom rule with its own entropy threshold, dropping low-randomness placeholder matches. Every other (structural) built-in detector is never gated by entropy.
4. **Verification** — eligible findings are checked against the live provider API.

:::tip
You don't have to understand the pipeline to use Leakwatch — but it explains why scans are fast and why some findings show a verification status while others don't. See [How It Works](#/getting-started/how-it-works) for the full picture.
:::

## What Leakwatch is *not*

To set expectations accurately:

- It does **not** rewrite Git history or remove secrets for you — it finds and reports them, and (with `--remediation`) tells you how to rotate them.
- Slack scanning covers **message text only**; scanning the *contents* of uploaded files is not implemented.
- Verification is available for many but not all secret types — 10 detector types (such as JWTs and generic API keys) cannot be safely verified and are always reported as unverified.

## Next steps

- [Installation](#/getting-started/installation) — install via Homebrew, `go install`, Docker, or a prebuilt binary.
- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [How It Works](#/getting-started/how-it-works) — the architecture behind the scan.

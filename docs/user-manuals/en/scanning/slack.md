---
title: "Slack Workspace"
description: "Scan Slack messages and opt-in text attachments for leaked secrets."
---

# Slack Workspace

Developers frequently share credentials in chat — a token pasted into a channel for a quick test, a password sent in a DM, or a configuration file uploaded to an incident thread. `leakwatch scan slack` reads message text across your Slack workspace and, when explicitly enabled, text-like file attachments.

:::note
File attachment scanning is opt-in. Use `--include-files` and grant `files:read`; without the flag, Leakwatch downloads no attachments.
:::

## Basic usage

```bash
leakwatch scan slack
```

This command takes **no positional arguments**. All configuration is provided through flags or environment variables.

## Authentication

A Slack Bot Token is required. Provide it via the `--token` flag or the `LEAKWATCH_SLACK_TOKEN` environment variable. Using an environment variable is recommended so the token never appears in shell history or process listings.

```bash
export LEAKWATCH_SLACK_TOKEN=xoxb-...
leakwatch scan slack
```

### Required bot token scopes

The bot token must be associated with a Slack app that has the following OAuth scopes:

| Scope | Purpose |
|-------|---------|
| `channels:history` | Read messages in public channels the bot has joined. |
| `groups:history` | Read messages in private channels the bot has joined. |
| `im:history` | Read direct messages (required only with `--include-dms`). |
| `mpim:history` | Read group direct messages (required only with `--include-dms`). |
| `files:read` | Read file metadata and contents (required only with `--include-files`). |

## Flags

### Slack-specific

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--token` | string | — | Slack Bot Token. Prefer `LEAKWATCH_SLACK_TOKEN` env var. |
| `--channels` | string | all channels | Comma-separated list of channel names to scan. |
| `--exclude-channels` | string | — | Comma-separated list of channel names to skip. |
| `--since` | string (YYYY-MM-DD) | — | Scan messages posted on or after this date. |
| `--include-dms` | bool | `false` | Also scan direct messages and group DMs. |
| `--include-files` | bool | `false` | Download and scan bounded text-like file attachments. Requires `files:read`. |
| `--rate-limit` | float | `1/60` | Maximum Slack API requests per second (one request/minute). Raise only when the app's published Slack tier permits it. |

### Common scan flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Maximum attachment size buffered for scanning, in bytes. |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--exclude-detectors` | — | — | Detector IDs to exclude for this run. Repeatable; combined with `filter.exclude-detectors`. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Root-level flags `--config` and `--log-level` (default `warn`) also apply. Unlike every other scan subcommand, `scan slack` has no `--exclude` path-pattern flag — use `--exclude-channels` to skip whole channels instead.

## Examples

Scan all channels the bot has access to, using an environment variable for the token:

```bash
export LEAKWATCH_SLACK_TOKEN=xoxb-...
leakwatch scan slack
```

Scan specific channels and limit to messages since the start of the year:

```bash
leakwatch scan slack \
  --channels general,engineering,backend \
  --since 2026-01-01
```

Exclude noisy channels and include direct messages:

```bash
leakwatch scan slack \
  --exclude-channels random,social,giphy \
  --include-dms
```

Include text-like file attachments while lowering the per-file memory bound:

```bash
leakwatch scan slack \
  --include-files \
  --max-file-size 5242880
```

Raise the API request rate only for a Marketplace/internal app whose published tier permits it:

```bash
leakwatch scan slack --rate-limit 0.8 --format table
```

Save only verified active findings to a JSON file:

```bash
leakwatch scan slack \
  --only-verified \
  --format json \
  --output slack-findings.json
```

## Finding metadata

Each finding from a Slack scan includes message and channel metadata:

| Field | Description |
|-------|-------------|
| `channel` | The Slack channel **ID** where the finding was detected (e.g. `C0123456`) — not the human-readable name. |
| `channel_name` | The human-readable channel name (e.g. `engineering`), as a separate field from `channel`. |
| `message_user` | Slack user ID of the message author. There is no `author` field for Slack findings. |
| `message_ts` | Slack message timestamp (unique message ID). |
| `thread_ts` | Timestamp of the parent message, present only when the finding is in a threaded reply. |
| `file_path` | Synthetic `slack/<channel>/<filename>` path, present for findings from an attachment. |

## Performance considerations

Slack API requests are subject to method- and distribution-specific limits. The `--rate-limit` flag defaults to one request/minute, matching Slack's lowest published `conversations.history` limit for newly distributed non-Marketplace apps. Marketplace/internal apps with Tier 3 access can raise it deliberately.

When Slack responds with `429 Too Many Requests`, Leakwatch automatically honors the `Retry-After` header and retries the request rather than failing the scan outright.

Attachment downloads share the same request limiter. Leakwatch accepts only Slack-owned HTTPS download URLs, buffers at most `--max-file-size`, skips binary/NUL-containing content, and de-duplicates the same Slack file ID across messages.

Use `--channels` to target specific channels rather than scanning the entire workspace on every run. Combine with `--since` to scan only recent messages incrementally.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, findings reported. |
| `2` | Scan failed (missing token, authentication error, etc.). |
| `3` | Scan was interrupted (`Ctrl+C` / `SIGTERM`) before completing, and no findings had been reported. |

A scan summary is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

## See also

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Config File](#/configuration/config-file) — configure defaults in `.leakwatch.yaml`.
- [Ignoring Findings](#/configuration/ignoring-findings) — suppress known false positives.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [Git History](#/scanning/git-history) — scan committed history for secrets.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.

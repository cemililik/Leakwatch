# Leakwatch - Slack Workspace Scanning Guide

> **Document Version:** 1.1
> **Date:** 2026-08-11
> **Status:** Approved

---

> **Documentation role:** Supplemental Slack operations deep dive. The [Slack user manual](../user-manuals/en/scanning/slack.md) is authoritative for current flags and supported content.

## Table of Contents

1. [Why Scan Slack?](#1-why-scan-slack)
2. [Prerequisites](#2-prerequisites)
3. [Basic Usage](#3-basic-usage)
4. [Channel Filtering](#4-channel-filtering)
5. [Date Filtering](#5-date-filtering)
6. [Direct Message Scanning](#6-direct-message-scanning)
7. [File Scanning](#7-file-scanning)
8. [Rate Limiting](#8-rate-limiting)
9. [Output Formats](#9-output-formats)
10. [CI/CD Integration](#10-cicd-integration)
11. [Scan Flow](#11-scan-flow)
12. [Troubleshooting](#12-troubleshooting)
13. [Security Considerations](#13-security-considerations)

---

## 1. Why Scan Slack?

Slack is one of the most common places where secrets are accidentally leaked. Developers routinely paste API keys, database credentials, and tokens into channels during debugging, onboarding, or incident response. Unlike code repositories, Slack messages often bypass pre-commit hooks and code review, making them a blind spot for most security programs.

### Common Leak Scenarios

| Scenario | Description |
|----------|-------------|
| **Debugging sessions** | Developers paste environment variables or API keys to troubleshoot issues |
| **Onboarding** | New team members receive credentials via direct messages |
| **Incident response** | Database connection strings shared during outage triage |
| **Bot integrations** | Webhook URLs and tokens posted when configuring integrations |
| **Configuration sharing** | `.env` file contents or config snippets pasted into channels |
| **File uploads** | Credential files, private keys, or config archives uploaded to channels |

---

## 2. Prerequisites

### 2.1 Creating a Slack Bot Token

To scan a Slack workspace, you need a Slack Bot Token (`xoxb-...`) with the appropriate OAuth scopes.

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps) and click **Create New App**.
2. Select **From scratch**, name the app (e.g., "Leakwatch Scanner"), and choose your workspace.
3. Navigate to **OAuth & Permissions** in the sidebar.
4. Under **Bot Token Scopes**, add the required scopes listed below.
5. Click **Install to Workspace** and authorize the app.
6. Copy the **Bot User OAuth Token** (`xoxb-...`).

### 2.2 Required OAuth Scopes

| Scope | Purpose |
|-------|---------|
| `channels:history` | Read messages in public channels |
| `channels:read` | List public channels |
| `groups:history` | Read messages in private channels the bot is a member of |
| `groups:read` | List private channels the bot is a member of |
| `im:read` | List direct-message conversations (only if `--include-dms` is used) |
| `im:history` | Read direct messages (only if `--include-dms` is used) |
| `mpim:read` | List group direct-message conversations (only if `--include-dms` is used) |
| `mpim:history` | Read group direct messages (only if `--include-dms` is used) |
| `files:read` | Read uploaded file content (only if `--include-files` is used) |

> **Note:** The bot can only read messages in channels it has been invited to. For private channels, you must explicitly add the bot to each channel.

### 2.3 Providing the Token

The Slack Bot Token can be provided in two ways:

```bash
# Via the --token flag
leakwatch scan slack --token xoxb-your-token-here

# Via the LEAKWATCH_SLACK_TOKEN environment variable (recommended)
export LEAKWATCH_SLACK_TOKEN=xoxb-your-token-here
leakwatch scan slack
```

---

## 3. Basic Usage

```bash
# Scan the entire workspace (all channels the bot can access)
leakwatch scan slack

# Scan with explicit token
leakwatch scan slack --token xoxb-your-token-here

# Scan and write results to a file
leakwatch scan slack --output slack-results.json

# Scan with only verified findings
leakwatch scan slack --only-verified

# Scan with minimum severity filter
leakwatch scan slack --min-severity high
```

---

## 4. Channel Filtering

### 4.1 Including Specific Channels

Use the `--channels` flag to scan only specific channels. Provide a comma-separated list of channel names:

```bash
# Scan only the engineering and devops channels
leakwatch scan slack --channels "engineering,devops"

# Scan a single channel
leakwatch scan slack --channels "incident-response"
```

### 4.2 Excluding Channels

Use the `--exclude-channels` flag to skip specific channels:

```bash
# Skip noisy channels
leakwatch scan slack --exclude-channels "random,social,watercooler"

# Combine with other flags
leakwatch scan slack --exclude-channels "random" --min-severity high
```

### 4.3 Combining Filters

The `--channels` and `--exclude-channels` flags can be combined. When both are specified, the include filter is applied first, then the exclude filter removes any matching channels from the result.

```bash
# Scan all "team-" channels except team-social
leakwatch scan slack --channels "team-backend,team-frontend,team-infra,team-social" \
  --exclude-channels "team-social"
```

---

## 5. Date Filtering

Use the `--since` flag to scan only messages posted after a specific date. The date format is `YYYY-MM-DD`:

```bash
# Scan messages from the last month
leakwatch scan slack --since "2026-03-01"

# Scan messages from the start of the year
leakwatch scan slack --since "2026-01-01"

# Combine with channel filtering
leakwatch scan slack --channels "engineering" --since "2026-03-01"
```

This is particularly useful for periodic scans where you only need to check new messages since the last scan.

---

## 6. Direct Message Scanning

By default, Leakwatch scans only public and private channels. To include direct messages (DMs) and group DMs, use the `--include-dms` flag:

```bash
# Include direct messages in the scan
leakwatch scan slack --include-dms
```

> **Privacy note:** Scanning direct messages has significant privacy implications. Ensure you have organizational approval and that your employees are aware that DMs may be scanned for security purposes. Many organizations restrict DM scanning to incident response scenarios or require explicit consent. The bot's OAuth scopes `im:read`, `im:history`, `mpim:read`, and `mpim:history` must be granted for this feature to work.

---

## 7. File Scanning

File scanning is opt-in. Add `--include-files` and grant the bot `files:read` to download and scan text-like attachments:

```bash
leakwatch scan slack --include-files --max-file-size 5242880
```

Leakwatch only sends the bot token to Slack-owned HTTPS download URLs. File metadata and downloads use separate limiter buckets and bounded 429 retry policies without consuming each other's or history capacity. Attachment chunks transfer with direct backpressure; content that exceeds `--max-file-size` or fails the conservative UTF-8 text classifier is skipped even when MIME metadata is empty or spoofed. The same Slack file ID is downloaded at most once per scan.

---

## 8. Rate Limiting

### 8.1 Slack API Rate Limits

Slack assigns limits per method and app distribution model. Its current
`conversations.history` contract is Tier 3 for Marketplace and internal
customer-built apps, but one request per minute with a 15-item page limit for
new commercially distributed non-Marketplace apps. Consult Slack's current
method documentation for your app rather than assuming one workspace-wide
tier.

### 8.2 Configuring the Rate Limit

Leakwatch keeps independent operation buckets because Slack applies Web API limits per method/workspace/app. Defaults are one request/minute for the special `conversations.history` profile, Tier 2 (20+/minute) for `conversations.list`, Tier 4 (100+/minute) for `files.info`, and a separate conservative 100/minute client-side cap for attachment downloads. The `--rate-limit` flag explicitly replaces every bucket with one common **per-operation** requests-per-second ceiling:

```bash
# Default rate (one request/minute)
leakwatch scan slack

# Higher rate for a Marketplace/internal app with Tier 3 history access
leakwatch scan slack --rate-limit 0.8
```

Leakwatch also honors Slack's `Retry-After` response and performs bounded retries. Raising the local cap does not override Slack's server-side contract; reduce it if you still receive rate limits.

---

## 9. Output Formats

Leakwatch supports five output formats for Slack scan results:

| Format | Flag | Use Case |
|--------|------|----------|
| **JSON** | `--format json` | Automation, scripts, API integration |
| **SARIF** | `--format sarif` | GitHub Security, IDE integration |
| **CSV** | `--format csv` | Spreadsheet tools, Excel |
| **Table** | `--format table` | Human-readable terminal output |
| **GitHub** | `--format github` | Inline pull-request annotations in GitHub Actions |

```bash
# JSON output (default)
leakwatch scan slack --format json --output slack-results.json

# SARIF output for security dashboards
leakwatch scan slack --format sarif --output slack-results.sarif

# CSV for spreadsheet analysis
leakwatch scan slack --format csv --output slack-results.csv

# Table output for quick terminal review
leakwatch scan slack --format table
```

### Processing JSON Output

```bash
# Filter findings by severity
leakwatch scan slack --format json --output results.json
jq '[.[] | select(.severity == "critical")]' results.json

# Group by channel
jq 'group_by(.source.channel_name) | map({channel: .[0].source.channel_name, count: length})' results.json

# List unique users who posted secrets
jq -r '.[].source.message_user' results.json | sort -u
```

---

## 10. CI/CD Integration

### Scheduled Slack Scan with GitHub Actions

```yaml
name: Scheduled Slack Scan

on:
  schedule:
    # Run every Monday at 08:00 UTC
    - cron: "0 8 * * 1"
  workflow_dispatch:

jobs:
  slack-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install Leakwatch
        run: go install github.com/HodeTech/leakwatch@latest

      - name: Scan Slack workspace
        env:
          LEAKWATCH_SLACK_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
        run: |
          leakwatch scan slack \
            --since "$(date -d '7 days ago' +%Y-%m-%d)" \
            --exclude-channels "random,social" \
            --min-severity medium \
            --format sarif \
            --output slack-results.sarif

      - name: Upload SARIF results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: slack-results.sarif

      - name: Notify on findings
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          channel-id: "security-alerts"
          slack-message: "Leakwatch found secrets in Slack messages. Review the GitHub Security tab for details."
        env:
          SLACK_BOT_TOKEN: ${{ secrets.SLACK_ALERT_TOKEN }}
```

> **Note:** Use a separate Slack Bot Token for the alert notification step. Do not reuse the scanning token for posting messages.

---

## 11. Scan Flow

```mermaid
flowchart TD
    A["leakwatch scan slack"] --> B["Resolve Token"]
    B --> C{"Token provided?"}
    C -->|"No"| D["Error: token required"]
    C -->|"Yes"| E["Authenticate (AuthTest)"]
    E --> F{"Auth OK?"}
    F -->|"No"| G["Error: auth failed"]
    F -->|"Yes"| H["List Channels"]

    H --> I["Apply Channel Filters"]
    I --> J["Rate Limiter"]

    J --> K["Fetch Message History"]
    K --> L{"--since filter?"}
    L -->|"Yes"| M["Skip old messages"]
    L -->|"No"| N["Process all messages"]
    M --> N

    N --> O{"--include-files?"}
    O -->|"Yes"| P["Fetch bounded text attachments"]
    O -->|"No"| R
    P --> R["Secret Detection Engine"]

    R --> S["Verification"]
    S --> T["Apply Severity Filter"]
    T --> U["Format Output"]

    U --> V["JSON"]
    U --> W["SARIF"]
    U --> X["CSV"]
    U --> Y["Table"]

    style D fill:#ffe0e0,stroke:#cc0000
    style G fill:#ffe0e0,stroke:#cc0000
```

---

## 12. Troubleshooting

### 12.1 Token Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `slack bot token is required` | No token provided | Set `LEAKWATCH_SLACK_TOKEN` or use `--token` |
| `slack auth test failed` | Token is invalid or revoked | Regenerate the token from the Slack App dashboard |
| `missing_scope` | Bot lacks required OAuth scopes | Add the missing scope under **OAuth & Permissions** and reinstall the app |
| No messages from private channels | Bot is not a channel member | Invite the bot to the private channel with `/invite @leakwatch` |

### 12.2 Rate Limiting

| Problem | Cause | Solution |
|---------|-------|----------|
| `slack_rate_limited` errors in logs | API rate limit exceeded | Lower `--rate-limit` (e.g., `--rate-limit 5`) |
| Scan is very slow | Rate limit set too low | Increase `--rate-limit` if your Slack plan allows higher quotas |
| Intermittent timeouts | Network instability or Slack API issues | Retry the scan; consider running from a stable network |

### 12.3 No Findings

| Problem | Cause | Solution |
|---------|-------|----------|
| Zero findings reported | No secrets in scanned messages | Verify by scanning a known test channel with a dummy (revoked) secret |
| Zero findings with `--since` | Date filter too restrictive | Use an earlier date or remove the filter |
| Zero findings with `--only-verified` | Secrets found but not verified as active | Run without `--only-verified` to see all findings |
| Zero findings with `--min-severity` | All findings below severity threshold | Lower the threshold (e.g., `--min-severity low`) |

---

## 13. Security Considerations

### 13.1 Token Storage

- **Never hard-code** the Slack Bot Token in scripts, configuration files, or CI/CD pipeline definitions.
- Store the token in a secrets manager (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets).
- Use the `LEAKWATCH_SLACK_TOKEN` environment variable rather than the `--token` flag in automated environments to avoid token exposure in process listings.

### 13.2 Token Permissions

- Grant only the minimum required scopes. If you do not need DM scanning, omit `im:history` and `mpim:history`.
- Regularly audit the Slack app's scope and access. Remove the app from workspaces where scanning is no longer needed.
- Rotate the Bot Token periodically according to your organization's key rotation policy.

### 13.3 Scan Output

- Leakwatch redacts secret values in output by default. Use `--show-raw` only when necessary for incident investigation.
- Store scan results in a secure location with restricted access. Treat SARIF and JSON output files as sensitive data.
- Do not post scan results containing raw secrets back into Slack channels.

### 13.4 Logging

- Leakwatch never logs discovered secret content. However, channel names and user IDs may appear in debug logs.
- In production, use `--log-level warn` or higher to minimize log verbosity.
- Do not enable debug logging in shared CI/CD environments where logs are broadly accessible.

---

## Related Documents

- [Architecture Design](../architecture/03-ARCHITECTURE.md)
- [Cloud Storage Scanning Guide](cloud-scanning.md)
- [Container Image Scanning Guide](container-scanning.md)
- [Development Standards](../standards/04-DEVELOPMENT-STANDARDS.md)
- [Roadmap](../05-ROADMAP.md)

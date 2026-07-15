<div align="center">

<a href="https://hodetech.github.io/Leakwatch/"><img src="docs/assets/banner.png" alt="Leakwatch — detect, verify & report leaked secrets" width="100%"></a>

**Detect, verify & report leaked secrets across code, Git history, containers, and the cloud.**
Open source (MIT) · single binary · built for CI.

[![CI](https://github.com/HodeTech/Leakwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/HodeTech/Leakwatch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/HodeTech/Leakwatch?sort=semver&color=e6394d)](https://github.com/HodeTech/Leakwatch/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/HodeTech/leakwatch)](https://goreportcard.com/report/github.com/HodeTech/leakwatch)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Leakwatch-2ea44f?logo=github)](https://github.com/marketplace/actions/leakwatch-secret-scanner)

[Quick Start](#quick-start) · [GitHub Action](#github-action) · [Verification](#is-it-still-live) · [Detectors](#detectors) · [Docs](https://hodetech.github.io/Leakwatch/)

</div>

---

## What is Leakwatch?

Leaked API keys, tokens, and passwords are one of the most common causes of breaches. **Leakwatch** finds them across your **codebase, full Git history, container images, and cloud storage** — and then *verifies whether each secret is still live*, so you spend time on real incidents instead of triaging noise.

```console
$ leakwatch scan fs .

SEVERITY  DETECTOR                    FILE        REDACTED                                         STATUS      REMEDIATION
--------  --------                    ----        --------                                         ------      -----------
CRITICAL  github-token                config.env  ****cdEF                                         unverified  -
CRITICAL  database-connection-string  config.env  postgres://admin:****@db.prod.internal:5432/app  unverified  -
CRITICAL  aws-access-key-id           config.env  ****MPLE                                         unverified  -

Found 3 secrets (3 critical).
```

> Secret values are **redacted by default** and never written to disk or logs. See [Security](#security).

## Features

- **6 scan sources** — filesystem, Git history (every commit), container images, AWS S3, Google Cloud Storage, Slack
- **63 built-in detectors** + **YAML custom rules** (no Go code needed)
- **54 live verifiers (85.7%)** — confirms whether a secret is *still active*, not just present
- **5 output formats** — JSON, SARIF, CSV, terminal table, and **GitHub inline annotations**
- **Drop-in distribution** — GitHub Action (Marketplace), Docker image, Homebrew, `go install`, single static binary
- **Secret-safe** — redacted output by default; secrets are never logged or stored
- **Fast & CI-ready** — Aho-Corasick keyword pre-filter + Shannon entropy, concurrent worker pool, exit-code aware, SARIF → Code Scanning

## Quick Start

```bash
# Homebrew (macOS/Linux)
brew install HodeTech/tap/leakwatch

# Go
go install github.com/HodeTech/leakwatch@latest

# Docker
docker run --rm -v "$(pwd):/scan" ghcr.io/hodetech/leakwatch:latest scan fs /scan
```

…or grab a prebuilt binary from the [releases page](https://github.com/HodeTech/Leakwatch/releases). Then:

```bash
leakwatch scan fs .                         # scan the current directory
leakwatch scan git .                        # scan full Git history
leakwatch scan image nginx:latest           # scan a container image
leakwatch scan fs . --format sarif -o results.sarif   # SARIF for Code Scanning
leakwatch scan git . --only-verified        # only secrets confirmed live (CLI verifies by default)
leakwatch init                              # generate a .leakwatch.yaml
```

<details>
<summary>More examples — cloud, Slack, multi-repo, remediation</summary>

```bash
leakwatch scan s3 my-bucket --prefix config/
leakwatch scan gcs my-bucket --prefix secrets/
leakwatch scan slack --token xoxb-... --channels general,engineering
leakwatch scan repos https://github.com/org/a.git https://github.com/org/b.git --parallel 5
leakwatch scan git . --since-commit HEAD~1   # only new commits (great for CI)
leakwatch scan fs . --remediation            # include rotation steps & doc links
```

</details>

## GitHub Action

Add secret scanning to any workflow in one line — published on the [GitHub Marketplace](https://github.com/marketplace/actions/leakwatch-secret-scanner):

```yaml
- uses: actions/checkout@v4
- uses: HodeTech/Leakwatch@v1
  with:
    scan-type: fs        # fs | git | image
```

- **`format: github`** → findings appear as **inline annotations** on the pull request.
- **`format: sarif` + `sarif-upload: true`** → findings show up as **Code Scanning alerts** (needs `permissions: security-events: write`).
- **`scan-diff: auto`** (git scans) → scans only the commits a PR/push introduces.

Exit codes (used for CI gating): **`0`** no findings · **`1`** findings reported · **`2`** error.

Full inputs and recipes: **[CI/CD Integration guide](docs/guides/ci-cd-integration.md)**.

## Is it still live?

Detection is only half the job — a key that was already rotated isn't an incident. For most secret types, Leakwatch makes a **controlled, read-only API call** to the provider to confirm status:

| Tier | What it means | Coverage |
|------|---------------|----------|
| **Live verified** | Read-only API call confirms the key is active / inactive | ~49 detectors |
| **Format checked** | Structurally validated where no safe live check exists | 5 detectors |
| **Not verifiable** | No public API (e.g. JWTs, private keys) — detected & triaged manually | 9 detectors |

That's **54 of 63 detectors (85.7%)** with verification. Verification is on by default for the CLI and off by default in the Action (to keep CI fast and offline) — flip it with `no-verify`.

## Why Leakwatch?

| | **Leakwatch** | TruffleHog | Gitleaks |
|---|---|---|---|
| License | **MIT** | AGPL-3.0 | MIT [^gl] |
| Live secret verification | **Yes (54 verifiers)** | Yes | No |
| Container image scanning | **Yes** | Yes | No |
| Cloud sources (S3 / GCS / Slack) | **Yes** | No | No |
| SARIF output | **Yes** | No [^th] | Yes |
| Custom rules | **YAML** | YAML | TOML |
| Single static binary | **Yes** | Yes | Yes |

**The short version:** Leakwatch is the only one of the three that is **both** permissively MIT-licensed **and** does live verification — plus container & cloud scanning and native SARIF, in one dependency-free binary.

[^gl]: The Gitleaks CLI is MIT; the official `gitleaks-action` runs under a commercial EULA and needs a (free) license key for **organization** accounts.
[^th]: TruffleHog emits JSON / plain / GitHub-Actions output and has no native SARIF formatter. All three tools use Aho-Corasick pre-filtering, Shannon-entropy filtering, and support custom rules.

## Detectors

**63 built-in detectors** across these categories, plus your own [YAML custom rules](docs/guides/custom-rules.md):

| Category | Examples |
|----------|----------|
| **Cloud** | AWS, GCP, Azure, Cloudflare, DigitalOcean, Heroku, Vercel |
| **AI / ML** | OpenAI, Anthropic, Hugging Face, DeepSeek |
| **Dev & CI/CD** | GitHub, GitLab, npm, PyPI, RubyGems, Docker Hub, CircleCI, Terraform Cloud |
| **Communication & Email** | Slack, Discord, Telegram, MS Teams, SendGrid, Mailgun, Postmark |
| **Payments** | Stripe, Coinbase |
| **Databases & Infra** | Postgres/MySQL/Mongo, Redis, Snowflake, RabbitMQ, Supabase, FTP, LDAP, Databricks |
| **Identity & Secrets** | JWT, private keys (RSA/SSH/PGP), Okta, Auth0, HashiCorp Vault, Doppler |
| **Monitoring & Security** | Datadog, Grafana, PagerDuty, New Relic, Sentry, Snyk, Twilio |
| **SaaS** | Shopify, Notion, Linear, Figma, Airtable |
| **Generic & Custom** | high-entropy generic keys · LaunchDarkly · SonarCloud · your YAML rules |

<details>
<summary><b>Full detector catalog (63) with IDs, severity &amp; verification</b></summary>

| Category | Detector | ID | Severity |
|----------|----------|----|----------|
| Cloud — AWS | Access Key ID | `aws-access-key-id` | Critical |
| Cloud — GCP | Service Account Key | `gcp-service-account` | Critical |
| Cloud — Azure | Storage Connection String | `azure-storage-key` | Critical |
| Cloud — Azure | Entra ID Client Secret | `azure-entra-secret` | Critical |
| Cloud — Cloudflare | API Token | `cloudflare-api-token` | Critical |
| Cloud — DigitalOcean | Personal Access Token | `digitalocean-token` | Critical |
| Cloud — Heroku | API Key | `heroku-api-key` | Critical |
| Cloud — Vercel | API Token | `vercel-token` | High |
| AI/ML | OpenAI API Key | `openai-api-key` | Critical |
| AI/ML | Anthropic API Key | `anthropic-api-key` | Critical |
| AI/ML | Hugging Face Token | `huggingface-token` | Critical |
| AI/ML | DeepSeek API Key | `deepseek-api-key` | Critical |
| DevTools | GitHub PAT | `github-token` | Critical |
| DevTools | GitHub OAuth & Installation Token (incl. stateless `ghs_`) | `github-oauth-token` | Critical |
| DevTools | GitLab PAT | `gitlab-pat` | Critical |
| DevTools | Bitbucket App Password | `bitbucket-app-password` | Critical |
| DevTools | NPM Token | `npm-token` | High |
| DevTools | PyPI Token | `pypi-api-token` | High |
| DevTools | RubyGems Key | `rubygems-api-key` | High |
| DevTools | Docker Hub PAT | `dockerhub-pat` | Critical |
| CI/CD | CircleCI Token | `circleci-token` | High |
| CI/CD | Terraform Cloud Token | `terraform-cloud-token` | Critical |
| Communication | Slack Bot Token | `slack-token` | Critical |
| Communication | Slack Webhook | `slack-webhook` | High |
| Communication | Discord Bot Token | `discord-bot-token` | Critical |
| Communication | Telegram Bot Token | `telegram-bot-token` | High |
| Communication | MS Teams Webhook | `teams-webhook` | High |
| Email | SendGrid API Key | `sendgrid-api-key` | Critical |
| Email | Mailgun API Key | `mailgun-api-key` | Critical |
| Email | Postmark Server Token | `postmark-server-token` | High |
| Payment | Stripe Live Key | `stripe-api-key-live` | Critical |
| Payment | Stripe Test Key | `stripe-api-key-test` | High |
| Payment | Coinbase API Key | `coinbase-api-key` | Critical |
| Blockchain | Infura API Key | `infura-api-key` | High |
| Database | Connection String (PG/MySQL/MongoDB) | `database-connection-string` | Critical |
| Database | Redis Connection | `redis-connection-string` | Critical |
| Database | Snowflake Credentials | `snowflake-credentials` | Critical |
| Database | RabbitMQ Connection | `rabbitmq-connection-string` | Critical |
| Database | Supabase Service Key | `supabase-service-key` | Critical |
| Infrastructure | FTP/SFTP Credentials | `ftp-credentials` | Critical |
| Infrastructure | LDAP Credentials | `ldap-credentials` | Critical |
| Infrastructure | Databricks PAT | `databricks-token` | Critical |
| Identity | JWT | `jwt` | High |
| Identity | Private Key (RSA/SSH/PGP) | `private-key` | Critical |
| Identity | Okta API Token | `okta-api-token` | Critical |
| Identity | Auth0 Management Token | `auth0-management-token` | Critical |
| Identity | HashiCorp Vault Token | `hashicorp-vault-token` | Critical |
| Monitoring | Datadog API Key | `datadog-api-key` | Critical |
| Monitoring | Grafana API Key | `grafana-api-key` | High |
| Monitoring | PagerDuty API Key | `pagerduty-api-key` | High |
| Monitoring | New Relic API Key | `newrelic-api-key` | High |
| Monitoring | Sentry Auth Token | `sentry-token` | High |
| Security | Snyk API Key | `snyk-api-key` | High |
| Security | Twilio API Key | `twilio-api-key` | Critical |
| Secrets Mgmt | Doppler Service Token | `doppler-token` | Critical |
| Feature Flags | LaunchDarkly SDK Key | `launchdarkly-sdk-key` | High |
| Code Quality | SonarCloud Token | `sonarcloud-token` | High |
| SaaS | Shopify Access Token | `shopify-access-token` | Critical |
| SaaS | Notion Token | `notion-token` | High |
| SaaS | Linear API Key | `linear-api-key` | High |
| SaaS | Figma PAT | `figma-pat` | High |
| SaaS | Airtable PAT | `airtable-pat` | High |
| Generic | Generic API Key | `generic-api-key` | Medium |

</details>

## Output formats

`--format` selects the output; `--output`/`-o` writes to a file instead of stdout.

| Format | Use it for |
|--------|-----------|
| `json` | Machine-readable findings (default) |
| `sarif` | GitHub Code Scanning / security tooling (v2.1.0) |
| `csv` | Spreadsheets (sanitized against formula injection) |
| `table` | Human-readable terminal output (severity-colored) |
| `github` | Inline pull request annotations in GitHub Actions |

## Configuration

Generate a starter file with `leakwatch init`, or write `.leakwatch.yaml`:

```yaml
scan:
  concurrency: 8
  max-file-size: 10485760        # 10 MB
detection:
  entropy: { enabled: true, threshold: 4.0 }
verification:
  enabled: true
  timeout: 10s
filter:
  exclude-paths: ["vendor/**", "node_modules/**", "**/*.lock"]
output:
  format: json
  show-raw: false
```

Use `.leakwatchignore` and `# leakwatch:ignore` markers to suppress known false positives. Details: **[Configuration guide](docs/guides/configuration.md)**.

## Security

- Secret values are **redacted by default** (e.g. `AKIA****MPLE`) and are **never written to disk or logs**. The raw value is only emitted if you explicitly pass `--show-raw`.
- Verification uses **controlled, read-only** API calls to providers; it makes no state-changing requests.
- Found a vulnerability? Please report it privately via a [GitHub security advisory](https://github.com/HodeTech/Leakwatch/security/advisories/new).

## Architecture

```mermaid
flowchart LR
    subgraph Sources["Sources (6)"]
        S1["Git"]
        S2["Filesystem"]
        S3["Container"]
        S4["AWS S3"]
        S5["GCS"]
        S6["Slack"]
    end
    subgraph Engine["Detection Engine"]
        E1["Aho-Corasick prefilter"]
        E2["Regex"]
        E3["Shannon entropy"]
    end
    subgraph Verify["Verification (54 verifiers)"]
        V1["Live API"]
        V2["Format validation"]
    end
    Sources -->|chunks| Engine
    Engine -->|findings| Verify
    Verify --> Output["JSON · SARIF · CSV · Table · GitHub"]
```

Deep dive: [Architecture](docs/architecture/03-ARCHITECTURE.md) · [ADRs](docs/decisions/README.md)

## Documentation

Full bilingual (EN/TR) manuals are at **[hodetech.github.io/Leakwatch](https://hodetech.github.io/Leakwatch/)**. Quick links:

[Getting Started](docs/guides/getting-started.md) ·
[Configuration](docs/guides/configuration.md) ·
[CI/CD](docs/guides/ci-cd-integration.md) ·
[Custom Rules](docs/guides/custom-rules.md) ·
[Container Scanning](docs/guides/container-scanning.md) ·
[Cloud Scanning](docs/guides/cloud-scanning.md) ·
[Git Scanning](docs/guides/git-scanning.md) ·
[Slack Scanning](docs/guides/slack-scanning.md) ·
[Verification](docs/guides/secret-verification.md) ·
[Docker](docs/guides/docker-usage.md) ·
[VS Code Extension](docs/guides/vscode-extension.md) ·
[Roadmap](docs/05-ROADMAP.md)

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/HodeTech/Leakwatch.git
cd Leakwatch && go mod download && go test ./...
```

## License

[MIT](LICENSE) © HodeTech — Leakwatch is maintained by [HodeTech](https://github.com/HodeTech).

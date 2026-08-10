---
title: "Detector Catalog"
description: "All 65 built-in detectors grouped by category, with their IDs, what they detect, and their default severity."
---

# Detector Catalog

Leakwatch ships **65 built-in detectors** that cover a wide range of credential types — from cloud provider access keys and AI API tokens to database connection strings and private cryptographic keys. Each detector has a stable ID and default severity. Verification capability is classified separately as direct-live, context-required, format-only, or unavailable; a registered verifier does not by itself prove live coverage.

This page lists every built-in detector. For verification coverage details see [Verification Coverage](#/verification/verification-coverage). To add your own patterns, see [Custom Rules](#/detectors/custom-rules).

## How to read this catalog

- **ID** — the stable string identifier used in config and output. Pass it to `filter.exclude-detectors` to skip a detector, or use it with `--min-severity` filtering ([Severity and Filtering](#/configuration/severity-and-filtering)).
- **Detects** — what the detector is looking for.
- **Severity** — `Critical`, `High`, or `Medium`. This is the default; it feeds the `--min-severity` flag and the `output.severity-threshold` config key.

---

## Cloud and Infrastructure

| ID | Detects | Severity |
|----|---------|----------|
| `aws-access-key-id` | AWS Access Key ID | Critical |
| `gcp-service-account` | GCP Service Account Key | Critical |
| `azure-storage-key` | Azure Storage Connection String | Critical |
| `azure-entra-secret` | Azure Entra ID Client Secret | Critical |
| `digitalocean-token` | DigitalOcean Personal Access Token | Critical |
| `cloudflare-api-token` | Cloudflare API Token | Critical |
| `heroku-api-key` | Heroku API Key | Critical |
| `vercel-token` | Vercel API Token | High |
| `terraform-cloud-token` | Terraform Cloud/Enterprise API Token | Critical |
| `hashicorp-vault-token` | HashiCorp Vault Token | Critical |
| `doppler-token` | Doppler Token — service (`dp.st.`), personal (`dp.pt.`), CLI/config (`dp.ct.`), and SCIM (`dp.scim.`) tokens | Critical |

## AI / ML

| ID | Detects | Severity |
|----|---------|----------|
| `openai-api-key` | OpenAI API Key — covers project-scoped (`sk-proj-`), service-account (`sk-svcacct-`), and legacy (`sk-`) key formats | Critical |
| `anthropic-api-key` | Anthropic API Key | Critical |
| `deepseek-api-key` | DeepSeek API Key | Critical |
| `huggingface-token` | Hugging Face API Token | Critical |

## Payments and Commerce

| ID | Detects | Severity |
|----|---------|----------|
| `stripe-api-key-live` | Stripe Live API Key | Critical |
| `stripe-api-key-test` | Stripe Test API Key | High |
| `coinbase-api-key` | Coinbase API Key | Critical |
| `shopify-access-token` | Shopify Access Token | Critical |

## Dev Tools, CI, and Packages

| ID | Detects | Severity |
|----|---------|----------|
| `github-token` | GitHub Personal Access Token — both the classic `ghp_` PAT and the fine-grained `github_pat_` PAT | Critical |
| `github-oauth-token` | GitHub OAuth2 & installation token — `gho_`/`ghu_`/`ghr_`/`ghs_`, including new stateless (JWT-format) `ghs_` installation tokens | Critical |
| `gitlab-pat` | GitLab credential — the classic `glpat-` personal access token plus deploy (`gldt-`), runner (`glrt-`), CI/CD build and trigger (`glcbt-`/`glptt-`), OAuth application secret (`gloas-`), and feed (`glft-`) prefixes; repository URLs are never trusted for verification routing | Critical |
| `bitbucket-app-password` | Bitbucket App Password | Critical |
| `circleci-token` | CircleCI Personal API Token | High |
| `npm-token` | NPM Access Token | High |
| `pypi-api-token` | PyPI API Token | High |
| `rubygems-api-key` | RubyGems API Key | High |
| `dockerhub-pat` | Docker Hub Personal Access Token | Critical |
| `sonarcloud-token` | SonarCloud/SonarQube Token | High |
| `snyk-api-key` | Snyk API Key | High |
| `databricks-token` | Databricks Personal Access Token | Critical |
| `launchdarkly-sdk-key` | LaunchDarkly SDK Key | High |

## Communication and Collaboration

| ID | Detects | Severity |
|----|---------|----------|
| `slack-token` | Slack Bot/User Token | Critical |
| `slack-webhook` | Slack Webhook URL | High |
| `teams-webhook` | Microsoft Teams Incoming Webhook URL | High |
| `discord-bot-token` | Discord Bot Token | Critical |
| `discord-webhook-url` | Discord Webhook URL | Critical |
| `telegram-bot-token` | Telegram Bot Token | High |
| `notion-token` | Notion Internal Integration Token | High |
| `linear-api-key` | Linear API Key | High |
| `figma-pat` | Figma Personal Access Token | High |
| `airtable-pat` | Airtable Personal Access Token | High |

## Email and Messaging Delivery

| ID | Detects | Severity |
|----|---------|----------|
| `sendgrid-api-key` | SendGrid API Key | Critical |
| `mailgun-api-key` | Mailgun API Key | Critical |
| `postmark-server-token` | Postmark Server API Token | High |
| `twilio-api-key` | Twilio API Key Secret explicitly paired with a nearby `SK...` Key SID; a bare SID is not a secret and is not reported | Critical |

## Monitoring and Observability

| ID | Detects | Severity |
|----|---------|----------|
| `datadog-api-key` | Datadog API Key | Critical |
| `newrelic-api-key` | New Relic API Key | High |
| `grafana-api-key` | Grafana API Key | High |
| `sentry-token` | Sentry Auth Token | High |
| `pagerduty-api-key` | PagerDuty API Key | High |

## Databases and Connection Strings

| ID | Detects | Severity |
|----|---------|----------|
| `database-connection-string` | Database Connection String | Critical |
| `redis-connection-string` | Redis Connection String | Critical |
| `rabbitmq-connection-string` | RabbitMQ Connection String | Critical |
| `snowflake-credentials` | Snowflake Connection Credentials | Critical |
| `supabase-service-key` | Supabase Personal Access Token (`sbp_`; stable legacy detector ID) | Critical |

## Identity and Access

| ID | Detects | Severity |
|----|---------|----------|
| `auth0-management-token` | Auth0 Management API Token | Critical |
| `okta-api-token` | Okta API Token | Critical |
| `ldap-credentials` | LDAP/LDAPS Bind Credentials | Critical |

## Web3

| ID | Detects | Severity |
|----|---------|----------|
| `infura-api-key` | Infura API Key | High |

## Generic and Cryptographic

| ID | Detects | Severity |
|----|---------|----------|
| `generic-api-key` | Generic API Key | Medium |
| `structured-config-secret` | Contextual secret value in JSON, YAML, TOML, XML, `.env`, or INI-style configuration | High |
| `jwt` | JSON Web Token | High |
| `private-key` | Private Key (RSA, SSH, DSA, EC, PGP), including PKCS8 `PRIVATE KEY` and password-protected `ENCRYPTED PRIVATE KEY` armor | Critical |
| `ftp-credentials` | FTP/SFTP Credentials | Critical |

---

**Total: 65 built-in detectors.**

## Filtering by severity

Findings are filterable by severity using `--min-severity` at the command line or `output.severity-threshold` in config. Only findings at or above the specified level are included in the output. See [Severity and Filtering](#/configuration/severity-and-filtering) for details.

## Excluding specific detectors

To skip one or more detectors entirely, add their IDs to `filter.exclude-detectors` in `.leakwatch.yaml`:

```yaml
filter:
  exclude-detectors:
    - generic-api-key
    - jwt
```

See [Severity and Filtering](#/configuration/severity-and-filtering) for the full filtering reference.

## Verification coverage

Some detectors have a direct-live verifier, some need trusted or companion context, others are format-only, and eleven have no verifier. See [Verification Coverage](#/verification/verification-coverage) for the complete breakdown.

## See also

- [Custom Rules](#/detectors/custom-rules) — define your own detection patterns in YAML.
- [Verification Coverage](#/verification/verification-coverage) — which detectors can be live-verified.
- [Severity and Filtering](#/configuration/severity-and-filtering) — filtering findings by severity or detector.

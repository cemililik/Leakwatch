---
title: "Verification Coverage"
description: "Which of the 64 built-in detectors are live-verified, format-validated only, or not verifiable — and what that means for triage."
---

# Verification Coverage

Leakwatch ships 64 built-in detectors and 54 verifiers, giving a coverage rate of **84.4%** (54 of 64 detector types have some form of verification — either live or format-only). This page maps every detector to its verification status so you know what to expect in your output.

## Live-verified (48 detector types)

For these types, Leakwatch makes a controlled, read-only API call to the provider and returns `verified_active` or `verified_inactive`. No data is created or modified; the call uses the minimum endpoint needed to confirm identity.

| Detector type | Provider |
|--------------|---------|
| `aws-access-key-id` | AWS STS (`GetCallerIdentity`) |
| `github-token` | GitHub REST API |
| `github-oauth-token` | GitHub REST API |
| `gitlab-pat` | GitLab REST API (targets a self-hosted GitLab host when one is captured alongside the token; falls back to gitlab.com) |
| `slack-token` | Slack Web API |
| `openai-api-key` | OpenAI API |
| `anthropic-api-key` | Anthropic API |
| `deepseek-api-key` | DeepSeek API |
| `huggingface-token` | Hugging Face API |
| `sendgrid-api-key` | SendGrid Web API (a `403` from a narrowly scoped/restricted key is treated as `verified_active`, not inactive, since the key itself is valid — only `401` maps to `verified_inactive`) |
| `mailgun-api-key` | Mailgun API (auto-detects and calls the correct EU vs. US regional endpoint) |
| `postmark-server-token` | Postmark API |
| `stripe-api-key-live` | Stripe API |
| `stripe-api-key-test` | Stripe API |
| `digitalocean-token` | DigitalOcean API |
| `cloudflare-api-token` | Cloudflare API |
| `heroku-api-key` | Heroku Platform API |
| `vercel-token` | Vercel REST API |
| `npm-token` | npm Registry API |
| `pypi-api-token` | PyPI API |
| `rubygems-api-key` | RubyGems API |
| `dockerhub-pat` | Docker Hub API |
| `circleci-token` | CircleCI API |
| `terraform-cloud-token` | Terraform Cloud API |
| `discord-bot-token` | Discord API |
| `telegram-bot-token` | Telegram Bot API |
| `sentry-token` | Sentry API |
| `pagerduty-api-key` | PagerDuty API |
| `newrelic-api-key` | New Relic API |
| `grafana-api-key` | Grafana API |
| `datadog-api-key` | Datadog API |
| `snyk-api-key` | Snyk API |
| `twilio-api-key` | Twilio API (authenticates with the API Key SID paired to its API Key Secret; without the paired secret the result is `unverified`, never a false `verified_inactive`) |
| `doppler-token` | Doppler API |
| `launchdarkly-sdk-key` | LaunchDarkly API |
| `sonarcloud-token` | SonarCloud API |
| `shopify-access-token` | Shopify Admin API |
| `notion-token` | Notion API |
| `linear-api-key` | Linear API |
| `figma-pat` | Figma REST API |
| `airtable-pat` | Airtable API |
| `okta-api-token` | Okta API (targets the org domain captured alongside the token) |
| `auth0-management-token` | Auth0 Management API (targets the tenant decoded from the token's own JWT `iss` claim) |
| `databricks-token` | Databricks REST API (calls the workspace host captured alongside the token) |
| `bitbucket-app-password` | Bitbucket REST API |
| `supabase-service-key` | Supabase API |
| `infura-api-key` | Infura API |
| `teams-webhook` | Microsoft Teams |

## Format-validated only (6 detector types)

These verifiers run entirely offline. No network request is made. Because a valid format does not prove a credential is active, all six always return `unverified` regardless of whether the format check passes or fails.

| Detector ID | What is validated | Why no live check |
|-------------|------------------|------------------|
| `gcp-service-account` | JSON structure (`type`, `project_id`, `private_key_id`, `client_email`) | Live check requires a GCP OAuth2 token exchange, which has side effects |
| `rabbitmq-connection-string` | AMQP URL parsed successfully | No public unauthenticated health endpoint |
| `snowflake-credentials` | Password length and host substring check | Live check requires a JDBC/ODBC database connection |
| `azure-storage-key` | Format check | Requires per-account HMAC signing; no generic identity endpoint |
| `azure-entra-secret` | Format check | Client credential flow would create sessions |
| `coinbase-api-key` | Character-set and length check | Coinbase's legacy API authenticates with HMAC-SHA256 request signing that requires the paired secret, which the detector cannot reliably associate with the key; live verification is not attempted so a real key is never misreported as inactive |

## Not verifiable (10 detector types)

These detector types have no verifier at all. Findings from them are always `unverified`. This is **not** because they are unimportant — they are detected and reported in full — but because no public verification API exists, or because any verification attempt would have side effects.

| Detector ID | Reason |
|-------------|--------|
| `jwt` | A JWT can be issued by any party; there is no universal validation endpoint |
| `private-key` | No provider to call; active use cannot be detected remotely |
| `generic-api-key` | Unknown provider by definition |
| `database-connection-string` | Connecting would create sessions on the target database |
| `redis-connection-string` | Connecting would open a live connection to the Redis instance |
| `ftp-credentials` | No safe read-only FTP probe |
| `ldap-credentials` | LDAP bind would create an authenticated session |
| `slack-webhook` | Confirming a webhook is active requires sending a message |
| `hashicorp-vault-token` | Vault token validation requires knowing the Vault endpoint |
| `discord-webhook-url` | Confirming a webhook is active requires posting a message to it |

:::note
"Not verifiable" does not mean "not found". All 10 of these types are still detected and appear in your output. They require manual triage to determine whether the credential is live and whether it needs rotation.
:::

## Coverage summary

| Category | Count |
|----------|-------|
| Live-verified | 48 |
| Format-validated only | 6 |
| Not verifiable | 10 |
| **Total detectors** | **64** |
| **Verifiers (any coverage)** | **54 (84.4%)** |

## See also

- [How Verification Works](#/verification/how-verification-works) — the two verification modes, statuses, and the verification engine.
- [Detector Catalog](#/detectors/detector-catalog) — the full list of built-in detectors with severities.

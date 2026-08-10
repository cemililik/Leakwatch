---
title: "Verification Coverage"
description: "Which of the 65 built-in detectors are live-verified, context-required, format-only, or not verifiable — and what that means for triage."
---

# Verification Coverage

Leakwatch ships **65 built-in detectors** and 54 registered verifier implementations. Registry presence is not the same as live capability: **41** detectors can make a live check in the normal production path, **7** require trusted operator or companion context, **6** perform offline format validation only, and **11** have no verifier. This page maps every detector to its actual verification contract.

## Live-verified (41 detector types)

For these types, Leakwatch can make a controlled, non-destructive provider check in the normal production path. A contract-valid success can return `verified_active`; only a definitive authentication rejection on the correct issuer can return `verified_inactive`. Ambiguous responses remain `verify_error`.

| Detector type | Provider |
|--------------|---------|
| `aws-access-key-id` | AWS STS (`GetCallerIdentity`) |
| `gitlab-pat` | GitLab REST API (targets a self-hosted GitLab host when one is captured alongside the token; falls back to gitlab.com) |
| `slack-token` | Slack Web API |
| `openai-api-key` | OpenAI API |
| `anthropic-api-key` | Anthropic API |
| `deepseek-api-key` | DeepSeek API |
| `huggingface-token` | Hugging Face API |
| `sendgrid-api-key` | SendGrid Web API (`401` is inactive; `403`, including permission denial, remains `verify_error`) |
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
| `newrelic-api-key` | New Relic NerdGraph (bounded official US/EU fallback; inactive only when both regions return `401`) |
| `doppler-token` | Doppler API |
| `launchdarkly-sdk-key` | LaunchDarkly API |
| `sonarcloud-token` | SonarCloud API |
| `notion-token` | Notion API |
| `linear-api-key` | Linear API |
| `figma-pat` | Figma REST API |
| `airtable-pat` | Airtable API |
| `okta-api-token` | Okta API (targets the org domain captured alongside the token) |
| `auth0-management-token` | Auth0 Management API (targets the tenant decoded from the token's own JWT `iss` claim) |
| `databricks-token` | Databricks REST API (calls the workspace host captured alongside the token) |
| `bitbucket-app-password` | Bitbucket REST API |
| `supabase-service-key` | Supabase Management API (`sbp_` personal access token; `401` is inactive, `403` remains `verify_error`) |
| `infura-api-key` | Infura API |
| `teams-webhook` | Microsoft Teams |

## Requires trusted or companion context (7 detector types)

These implementations are registered, but a bare detector finding is not enough to choose a safe issuer or authenticate the verification request. When the required context is absent, Leakwatch makes no unsafe guess and returns `unverified`.

| Detector ID | Required context | Production behavior |
|-------------|------------------|---------------------|
| `grafana-api-key` | Trusted Grafana instance origin supplied with `--grafana-instance-url` | Calls only the validated HTTPS instance. Repository content and finding metadata cannot choose the target; `401` is inactive only on that trusted issuer. |
| `twilio-api-key` | Paired API Key SID plus an operator-trusted regional API origin (US1/IE1/AU1) | A bare `SK...` SID is a public identifier and is not reported. Twilio treats the API Key Secret as opaque, so the detector does not assume a fixed length or alphabet: it emits the value of an explicit API Key Secret assignment only when it can pair it one-to-one with an explicitly assigned nearby `SK...` SID in the same logical block. The secret stays in `Raw`; only non-secret SIDs enter context. Production has no trusted regional origin yet, so it makes no request and returns `unverified`; on a configured origin only `401` is inactive and permission `403` remains `verify_error`. |
| `shopify-access-token` | Operator-trusted issuing store origin | Finding metadata is never trusted for routing. Production has no trusted store origin, so it makes no request and returns `unverified`. The prepared verifier uses the pinned 2026-07 Admin GraphQL shop identity query; only `401` on the selected store is inactive. |
| `github-token` | Trusted GitHub.com or GitHub Enterprise Server API origin | GHES uses the same `ghp_` and `github_pat_` formats as GitHub.com. The current production registration has no trusted origin, so it makes no request and returns `unverified`. |
| `github-oauth-token` | Trusted GitHub.com or GitHub Enterprise Server API origin | With a trusted issuer, `gho_`/`ghu_` use `/user` and `ghs_` uses the installation repositories endpoint. `ghr_` refresh tokens remain `unverified` without a request because exchanging one rotates it. The current production registration has no trusted origin, so every subtype makes no request and returns `unverified`. |
| `datadog-api-key` | Trusted Datadog site/API origin | Datadog keys are site-bound across US1/US3/US5/EU/AP1/AP2/UK1/US1-FED/US2-FED. The current production registration has no trusted site, so it makes no request and returns `unverified`. |
| `snyk-api-key` | Trusted Snyk regional, government, or private API origin | A key rejected by the wrong Snyk region is not proof of revocation. On a trusted origin only `401` proves inactivity; `403` remains `verify_error` because it can mean a valid token lacks API-plan or endpoint permission. The current production registration has no trusted origin, so it makes no request and returns `unverified`. |

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

## Not verifiable (11 detector types)

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
| `structured-config-secret` | Contextual fallback can identify a secret role but not the credential provider or issuer |

:::note
"Not verifiable" does not mean "not found". All 11 of these types are still detected and appear in your output. They require manual triage to determine whether the credential is live and whether it needs rotation.
:::

## Coverage summary

| Category | Count |
|----------|-------|
| Live-verified | 41 |
| Requires trusted/companion context | 7 |
| Format-validated only | 6 |
| Not verifiable | 11 |
| **Total detectors** | **65** |
| **Registered verifier implementations** | **54 (83.1%)** |

## See also

- [How Verification Works](#/verification/how-verification-works) — the two verification modes, statuses, and the verification engine.
- [Detector Catalog](#/detectors/detector-catalog) — the full list of built-in detectors with severities.

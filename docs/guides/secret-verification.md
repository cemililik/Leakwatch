# Leakwatch - Secret Verification Guide

> **Document Version:** 1.2
> **Date:** 2026-08-10
> **Status:** Approved

---

## 1. What is Secret Verification?

Secret verification is the process of checking whether a detected secret is actually active and valid. Leakwatch ships with **65 detectors (61 packages)** and **54 registered verifier implementations (51 packages)**. Registry presence is not live capability: **41** detectors support a direct live check, **7** require trusted issuer, region, or companion context, **6** are format-only, and **11** have no verifier.

Verification is classified into three methods:
- **Direct live API verification** (41 detectors) -- controlled, non-destructive API calls available in the normal production path
- **Context-required verification** (7 detectors) -- a trusted issuer, region, or paired credential is required before any safe request
- **Format validation** (6 detectors) -- structural checks (decode, parse, validate format) without network calls

**Why it matters:**

- **Reduces false positives** -- A regex match alone cannot tell you whether a string is a real, active secret. Verification eliminates noise by confirming status with the provider.
- **Prioritizes remediation** -- Teams can focus on verified active secrets first instead of triaging hundreds of unconfirmed findings.
- **Provides context** -- Verification results include extra metadata (e.g., AWS account ID, GitHub username) that helps identify the owner of the leaked credential.

```mermaid
flowchart LR
    subgraph Scan["Detection Phase"]
        S1["Source\n(fs/git/image)"] --> E1["Detection\nEngine"]
    end

    subgraph Verify["Verification Phase"]
        E1 -->|Findings| R1{"Verifier\nRegistry"}
        R1 -->|Match| API["Provider API\n(STS, GitHub, etc.)"]
        R1 -->|No match| U["Status:\nunverified"]
        API -->|Success| VA["Status:\nverified_active"]
        API -->|Auth error| VI["Status:\nverified_inactive"]
        API -->|Network error| VE["Status:\nverify_error"]
    end

    VA --> Out["Output\n(JSON/SARIF/CSV/Table)"]
    VI --> Out
    VE --> Out
    U --> Out
```

---

## 2. Verification Statuses

Every finding in Leakwatch carries a verification status. Understanding these statuses is essential for effective triage.

| Status | Description | Action Required |
|--------|-------------|-----------------|
| `verified_active` | Secret is **valid and active** -- the provider confirmed it works | **Immediate rotation required** |
| `verified_inactive` | Secret is **invalid or revoked** -- the provider gave a definitive authentication rejection under that verifier's contract | Low priority; may still warrant cleanup |
| `unverified` | Verification was not performed (no verifier, missing context, format-only capability, or `--no-verify`) | Manual review recommended |
| `verify_error` | An error occurred during verification (network timeout, rate limit, etc.) | Retry or verify manually |

```mermaid
stateDiagram-v2
    [*] --> Detection: Secret found
    Detection --> Verification: Verifier registered
    Detection --> unverified: No verifier available
    Verification --> verified_active: Credentials valid
    Verification --> verified_inactive: Credentials invalid/expired
    Verification --> verify_error: API error or timeout
```

---

## 3. Verified Detectors

Leakwatch provides 54 registered verifier implementations (51 packages) across three verification types. The following tables classify capability rather than equating registry count with live coverage.

### Direct Live API Verification (41 detectors)

These verifiers make a controlled, non-destructive API call to the provider to confirm whether the secret is active or inactive. The majority use HTTP GET; a small number (e.g., the Teams webhook verifier) use a non-destructive POST to a validation endpoint.

| Category | Detector | Detector ID | API Endpoint |
|----------|----------|-------------|-------------|
| **Cloud** | AWS Access Key | `aws-access-key-id` | STS `GetCallerIdentity` |
| **Cloud** | DigitalOcean Token | `digitalocean-token` | `api.digitalocean.com/v2/account` |
| **Cloud** | Cloudflare API Token | `cloudflare-api-token` | `api.cloudflare.com/client/v4/user/tokens/verify` |
| **Cloud** | Heroku API Key | `heroku-api-key` | `api.heroku.com/account` |
| **Cloud** | Vercel Token | `vercel-token` | `api.vercel.com/v2/user` |
| **AI/ML** | OpenAI API Key | `openai-api-key` | `api.openai.com/v1/models` |
| **AI/ML** | Anthropic API Key | `anthropic-api-key` | `api.anthropic.com/v1/models` |
| **AI/ML** | Hugging Face Token | `huggingface-token` | `huggingface.co/api/whoami-v2` |
| **AI/ML** | DeepSeek API Key | `deepseek-api-key` | `api.deepseek.com/models` |
| **DevTools** | GitLab PAT | `gitlab-pat` | `{host}/api/v4/user` (defaults to `gitlab.com`; honors a co-located self-hosted instance host) |
| **DevTools** | Bitbucket App Password | `bitbucket-app-password` | `api.bitbucket.org/2.0/user` |
| **DevTools** | NPM Token | `npm-token` | `registry.npmjs.org/-/npm/v1/user` |
| **DevTools** | PyPI Token | `pypi-api-token` | `upload.pypi.org/legacy/` |
| **DevTools** | RubyGems Key | `rubygems-api-key` | `rubygems.org/api/v1/api_key.json` |
| **DevTools** | Docker Hub PAT | `dockerhub-pat` | `hub.docker.com/v2/user/` (direct Bearer auth; no login/JWT-exchange step) |
| **CI/CD** | CircleCI Token | `circleci-token` | `circleci.com/api/v2/me` |
| **CI/CD** | Terraform Cloud Token | `terraform-cloud-token` | `app.terraform.io/api/v2/account/details` |
| **Communication** | Slack Bot Token | `slack-token` | `slack.com/api/auth.test` |
| **Communication** | Discord Bot Token | `discord-bot-token` | `discord.com/api/v10/users/@me` |
| **Communication** | Telegram Bot Token | `telegram-bot-token` | `api.telegram.org/bot{token}/getMe` |
| **Communication** | MS Teams Webhook | `teams-webhook` | `{webhook-url}` (non-destructive empty `{}` POST; 400 = active, 404 = inactive) |
| **Email** | SendGrid API Key | `sendgrid-api-key` | `api.sendgrid.com/v3/scopes` (`401` is inactive; `403`, including permission denial, remains `verify_error`) |
| **Email** | Mailgun API Key | `mailgun-api-key` | `api.mailgun.net/v3/domains`, retrying `api.eu.mailgun.net/v3/domains` if the US host reports inactive (US/EU are separate tenants) |
| **Email** | Postmark Server Token | `postmark-server-token` | `api.postmarkapp.com/server` |
| **Payment** | Stripe Live Key | `stripe-api-key-live` | `api.stripe.com/v1/charges?limit=1` |
| **Payment** | Stripe Test Key | `stripe-api-key-test` | `api.stripe.com/v1/charges?limit=1` |
| **DevTools** | Supabase Personal Access Token | `supabase-service-key` | Supabase Management API `api.supabase.com/v1/projects` (`sbp_` Bearer PAT; `401` is inactive, `403` remains inconclusive) |
| **Infrastructure** | Databricks PAT | `databricks-token` | `{workspace-host}/api/2.0/preview/scim/v2/Me` (workspace host captured alongside the token; no host means unverified) |
| **Identity** | Okta API Token | `okta-api-token` | `{domain}/api/v1/users/me` (org domain captured alongside the token) |
| **Identity** | Auth0 Management Token | `auth0-management-token` | `{tenant}/api/v2/` (tenant host decoded from the token's own `iss` JWT claim) |
| **Monitoring** | PagerDuty API Key | `pagerduty-api-key` | `api.pagerduty.com/users/me` |
| **Monitoring** | New Relic user API key | `newrelic-api-key` | Read-only NerdGraph `requestContext { userId }`; fixed official US/EU endpoints with bounded fallback. Only all-region 401 is inactive; 403 and partial failures remain inconclusive. |
| **Monitoring** | Sentry Auth Token | `sentry-token` | `sentry.io/api/0/` |
| **Secrets Mgmt** | Doppler Service Token | `doppler-token` | `api.doppler.com/v3/me` |
| **Feature Flags** | LaunchDarkly SDK Key | `launchdarkly-sdk-key` | `app.launchdarkly.com/api/v2/caller-identity` |
| **Code Quality** | SonarCloud Token | `sonarcloud-token` | `sonarcloud.io/api/authentication/validate` |
| **SaaS** | Notion Token | `notion-token` | `api.notion.com/v1/users/me` |
| **SaaS** | Linear API Key | `linear-api-key` | `api.linear.app/graphql` |
| **SaaS** | Figma PAT | `figma-pat` | `api.figma.com/v1/me` |
| **SaaS** | Airtable PAT | `airtable-pat` | `api.airtable.com/v0/meta/whoami` |
| **Blockchain** | Infura API Key | `infura-api-key` | `mainnet.infura.io/v3/{key}` |

### Requires Trusted or Companion Context (7 detectors)

These implementations are registered, but a bare detector finding cannot safely select the issuer or authenticate the verification request. Missing context produces `unverified` without a network request.

| Detector | Detector ID | Required context and behavior |
|----------|-------------|-------------------------------|
| Grafana service-account token | `grafana-api-key` | Trusted HTTPS instance origin from `--grafana-instance-url`; repository content cannot choose the target, and `401` is inactive only on that trusted issuer |
| Twilio API Key Secret | `twilio-api-key` | The detector treats the secret as opaque and reports an explicit API Key Secret assignment only when it pairs one-to-one with an explicitly assigned nearby `SK...` Key SID in the same logical block; bare SIDs are not findings. A trusted regional origin (US1/IE1/AU1) is still operator context, so production makes no request without it; `403` is permission-ambiguous and never inactive |
| Shopify Access Token | `shopify-access-token` | Operator-trusted issuing store origin; finding-controlled domains are ignored. The prepared verifier uses the pinned 2026-07 Admin GraphQL shop identity query, but production makes no request until trusted-store configuration exists |
| GitHub PAT | `github-token` | Trusted GitHub.com or GHES API origin; both issuers use `ghp_`/`github_pat_`, so the registered production verifier makes no request without explicit issuer trust |
| GitHub OAuth/App Token | `github-oauth-token` | Trusted GitHub.com or GHES API origin; `gho_`/`ghu_` use `/user`, `ghs_` uses `/installation/repositories`, and side-effectful `ghr_` refresh-token exchange is never attempted |
| Datadog API Key | `datadog-api-key` | Trusted Datadog site/API origin across US1/US3/US5/EU/AP1/AP2/UK1/US1-FED/US2-FED; the production verifier makes no request without it |
| Snyk API Key | `snyk-api-key` | Trusted Snyk regional, government, or private API origin; only `401` is inactive, while permission/plan `403` remains `verify_error`; production makes no request without a trusted origin |

### Format Validation (6 detectors)

These verifiers perform structural validation without making network calls. They check format and decode tokens without contacting the provider.

| Detector | Detector ID | Validation Method |
|----------|-------------|-------------------|
| Azure Storage Key | `azure-storage-key` | HMAC-SHA256 signature format validation |
| Azure Entra Secret | `azure-entra-secret` | OAuth2 client credential format check |
| GCP Service Account | `gcp-service-account` | JSON key file structure and private key parsing |
| RabbitMQ Connection | `rabbitmq-connection-string` | AMQP URL format validation (scheme, credentials, host) |
| Snowflake Credentials | `snowflake-credentials` | Connection string format and credential structure validation |
| Coinbase API Key | `coinbase-api-key` | Key-shape validation only; live verification needs HMAC-SHA256 request signing with the paired secret, which the detector cannot reliably supply, so the result is always `unverified` -- never a false active/inactive |

### Not Verifiable (11 detectors)

These detectors have no registered verifier, so their findings are always reported as `unverified`.

| Detector | Detector ID | Reason |
|----------|-------------|--------|
| JWT | `jwt` | No central issuer to query; validity depends on the signing key holder |
| Private Key | `private-key` | No remote verification endpoint; validity depends on deployment target |
| Generic API Key | `generic-api-key` | Unknown provider; no way to determine which API to call |
| HashiCorp Vault Token | `hashicorp-vault-token` | No verifier registered; would require reaching a typically internal, self-hosted Vault address |
| Database Connection String | `database-connection-string` | Requires direct database connection; intrusive and unsafe |
| Redis Connection | `redis-connection-string` | Requires direct network connection to typically internal Redis instance |
| FTP/SFTP Credentials | `ftp-credentials` | Requires direct connection to potentially internal FTP servers |
| LDAP Credentials | `ldap-credentials` | Requires direct connection to LDAP directory server |
| Slack Webhook | `slack-webhook` | Verification would send a message (side effect) |
| Discord Webhook URL | `discord-webhook-url` | Verification would post a message (side effect) |
| Structured Configuration Secret | `structured-config-secret` | Field context can identify a secret role but cannot determine the credential provider or issuer |

---

## 4. AWS Verification

### How It Works

The AWS verifier calls [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html) using the discovered Access Key ID and Secret Access Key. This is a read-only API call that returns identity information without performing any actions on the AWS account.

- **Detector ID:** `aws-access-key-id`
- **Required data:** Both the Access Key ID (`AKIA...`) and the corresponding Secret Access Key must be found in the same context.
- **API endpoint:** `sts.amazonaws.com` (us-east-1)

### What It Reveals

When credentials are active, the verifier returns:

| Field | Description |
|-------|-------------|
| `account` | AWS account ID |
| `arn` | Full ARN of the authenticated entity |
| `user_id` | IAM user or role ID |

### IAM Permissions

The `GetCallerIdentity` API requires **no specific IAM permissions**. It works with any valid AWS credentials regardless of attached policies. This makes it ideal for verification: even a key with zero permissions will return a successful response if the credentials are active.

### Example Output

```json
{
  "verification": {
    "status": "verified_active",
    "message": "AWS credentials are active",
    "extra_data": {
      "account": "123456789012",
      "arn": "arn:aws:iam::123456789012:user/deploy-bot",
      "user_id": "AIDAEXAMPLEUSERID"
    }
  }
}
```

If the credentials are invalid or expired:

```json
{
  "verification": {
    "status": "verified_inactive",
    "message": "AWS credentials are invalid or inactive"
  }
}
```

### Conditions for Skipping

If the Secret Access Key is not found alongside the Access Key ID, verification is skipped and the finding is marked as `unverified` with the message "secret access key not found."

---

## 5. GitHub Verification

### How It Works

GitHub.com and GitHub Enterprise Server (GHES) issue credentials with the same token prefixes. A token alone therefore cannot identify its issuer. Leakwatch sends a `GET /user` request only after a trusted GitHub API origin has been selected by operator-controlled configuration. The current production registration does not yet expose that configuration, so GitHub token findings return `unverified` without making a network request.

- **Detector IDs:** `github-token`, `github-oauth-token`
- **API endpoints:** trusted GitHub.com or GHES API origin plus `/user` for PAT/`gho_`/`ghu_`; `/installation/repositories` for `ghs_`
- **Headers:** `Authorization: Bearer <token>`, `User-Agent: leakwatch-verifier`

This fail-closed behavior prevents a valid GHES token from being sent to GitHub.com and incorrectly reported as inactive. Refresh tokens (`ghr_`) are detected but never exchanged because exchange rotates them; they remain `unverified` even when an issuer is trusted. When trusted-origin wiring is available, only an authentication rejection from the selected issuer and subtype-appropriate endpoint may produce `verified_inactive`.

### What It Reveals

When the token is active, the verifier returns:

| Field | Description |
|-------|-------------|
| `login` | GitHub username associated with the token |

### Response Handling

| HTTP Status | Verification Result |
|-------------|-------------------|
| No trusted API origin | `unverified` -- no request is made |
| `200 OK` from trusted origin | `verified_active` -- token is valid |
| `401 Unauthorized` from trusted origin | `verified_inactive` -- token is invalid or revoked for that issuer |
| Other | `verify_error` -- unexpected response |

### Example Output

```json
{
  "verification": {
    "status": "verified_active",
    "message": "GitHub token is active",
    "extra_data": {
      "login": "octocat"
    }
  }
}
```

---

## 6. CLI Flags

Leakwatch provides flags to control verification behavior on every scan command (`scan fs`, `scan git`, `scan image`, `scan s3`, `scan gcs`, `scan slack`, and `scan repos`).

| Flag | Default | Description |
|------|---------|-------------|
| `--no-verify` | `false` | Skip all secret verification |
| `--only-verified` | `false` | Only include findings with `verified_active` status in the output |
| `--min-severity` | `low` | Minimum severity level to report |

### Examples

```bash
# Fast scan without any verification API calls
leakwatch scan fs /path/to/project --no-verify

# Show only confirmed active secrets (highest confidence)
leakwatch scan git . --only-verified

# Combine: only verified critical findings
leakwatch scan git . --only-verified --min-severity critical
```

---

## 7. Rate Limiting and Concurrency

The verification engine manages API calls carefully to avoid overwhelming provider APIs and to stay within rate limits.

### Default Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| Concurrency | 4 workers | Number of parallel verification goroutines |
| Rate limit | 10 req/sec | Maximum verification requests per second (token bucket) |
| Timeout | 10 seconds | Per-finding timeout for the complete verification operation, including bounded provider-region fallback |

### How It Works

The verification engine uses a worker pool pattern with a shared rate limiter:

1. **Worker pool** -- A fixed number of goroutines (default 4) process verification jobs concurrently.
2. **Token bucket rate limiter** -- Before each API call, the worker acquires a token from a `golang.org/x/time/rate` limiter. If the bucket is empty, the worker waits until a token becomes available.
3. **Per-finding timeout** -- Each finding's complete verification operation has one context timeout (default 10s), including bounded provider-region fallback. If the provider does not respond in time, the finding is marked `verify_error`.
4. **Context cancellation** -- If the parent context is cancelled (e.g., the user presses Ctrl+C), all pending verifications are abandoned gracefully.

### Configuration

These settings can be adjusted in the `.leakwatch.yaml` configuration file:

```yaml
verification:
  enabled: true
  timeout: 10s
  concurrency: 4
  rate-limit: 10.0
```

---

## 8. Security Considerations

Verification involves sending discovered credentials to provider APIs. Keep the following in mind:

- **Credentials are transmitted over the network** -- The raw secret value is sent only to the verifier's fixed provider endpoint, credential-derived endpoint, or explicitly trusted operator-selected origin over HTTPS. Context-dependent verifiers make no request when a trustworthy destination is unavailable.
- **Leakwatch never logs raw secrets** -- Verifiers are designed to never log, persist, or cache the raw credential values. Only redacted values appear in logs.
- **Non-destructive operations only** -- All verification calls are controlled and non-destructive. The majority use HTTP GET; where a POST is required (e.g., the Teams webhook verifier), it targets a validation endpoint and does not cause state changes or side effects.
- **Network requirements** -- Verification requires outbound HTTPS access. In air-gapped or restricted environments, use `--no-verify` to skip verification entirely.
- **Provider rate limits** -- While Leakwatch applies its own rate limiting, provider-side rate limits may still apply. If you are verifying a large number of findings, consider the provider's documented rate limits.

---

## 9. Use Cases and Strategies

### CI/CD Pipeline: Two-Phase Approach

In CI/CD pipelines, speed matters. A two-phase approach balances speed with accuracy:

```bash
# Phase 1: Fast scan without verification (fail fast on regex matches)
leakwatch scan git . --since-commit HEAD~1 --no-verify --min-severity high
if [ $? -eq 1 ]; then
    echo "Potential secrets found, running verification..."

    # Phase 2: Verify only critical findings
    leakwatch scan git . --since-commit HEAD~1 --only-verified --min-severity critical
    if [ $? -eq 1 ]; then
        echo "CONFIRMED active secrets found! Blocking merge."
        exit 1
    fi
fi
```

### Triage Workflow

For security teams reviewing scan results:

1. Run a full scan with verification enabled (the default).
2. Address `verified_active` findings immediately -- these are confirmed live credentials.
3. Review `unverified` findings manually -- these may still be real secrets without an available verifier.
4. Deprioritize `verified_inactive` findings -- these are expired or revoked, but consider removing them from the codebase for hygiene.
5. Retry `verify_error` findings -- these may have failed due to transient network issues.

### Decision Tree

```mermaid
flowchart TD
    A["Start: Choose verification strategy"] --> B{"Environment?"}

    B -->|"CI/CD pipeline"| C{"Speed priority?"}
    B -->|"Security audit"| D["Full scan with verification\nleakwatch scan git . --only-verified"]
    B -->|"Air-gapped / restricted"| E["Skip verification\nleakwatch scan fs . --no-verify"]

    C -->|"Fast feedback"| F["Phase 1: No verification\nleakwatch scan git . --no-verify"]
    C -->|"Accuracy first"| D

    F --> G{"Findings?"}
    G -->|"Yes"| H["Phase 2: Verify critical\nleakwatch scan git . --only-verified --min-severity critical"]
    G -->|"No"| I["Pipeline passes"]

    H --> J{"Active secrets?"}
    J -->|"Yes"| K["Block pipeline\nNotify security team"]
    J -->|"No"| L["Pipeline passes\nLog for review"]
```

---

## 10. Next Steps

| Topic | Document |
|-------|----------|
| Getting started with Leakwatch | [Getting Started Guide](./getting-started.md) |
| Configuration file and options | [Configuration Guide](./configuration.md) |
| Running Leakwatch with Docker | [Docker Usage Guide](./docker-usage.md) |
| Architecture overview | [Architecture Document](../architecture/03-ARCHITECTURE.md) |

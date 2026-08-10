# Leakwatch - Secret Verifier Analysis

> **Document Version:** 2.1
> **Date:** 2026-08-11
> **Status:** Completed

## 1. Current State

Leakwatch has **65 built-in detectors (61 packages)** and **54 registered verifier implementations (51 packages)**. Registry coverage is 54/65 (83.1%), but this is not live capability: 39 detectors are direct-live, 9 require trusted issuer, region, or companion context, 6 are format-only, and 11 have no verifier.

All counts are verified by inspecting `detector.Register(` and `verifier.Register(` call sites.

| Metric | Value | Source |
|--------|-------|--------|
| Total Detectors | 65 (61 packages) | runtime registry guard (`cmd/stats_test.go`) |
| Verifiers Implemented | 54 (51 packages) | `grep -r "verifier.Register" internal/verifier/` |
| Registered-verifier coverage | 54/65 (83.1%) | Not a live-capability metric |
| Direct-live capabilities | 39 | Make real network/SDK calls in the normal production path |
| Context-required capabilities | 9 | Auth0, GitLab, Grafana, Twilio, Shopify, GitHub PAT/OAuth, Datadog, Snyk |
| Format-Only Verifiers | 6 | Structural/format checks only |
| Detectors Without Verifiers | 11 | Listed in section 2 |
| Verifier Architecture | `init()` + compile-time registration via `verifier.Register()` | |
| Verification Interface | `Verifier.Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult` | `internal/verifier/verifier.go` |

### Existing Verifier Patterns

All current verifiers follow a consistent pattern:

- **AWS** (`aws-access-key-id`): Uses STS `GetCallerIdentity` with the key pair (requires both Access Key ID in `Raw` and Secret Access Key in `RawV2`). Returns account/ARN metadata on success.
- **GitHub** (`github-token`, `github-oauth-token`): GitHub.com and GHES share token formats. Production has no operator-controlled trusted origin yet, so both return `unverified` without a request. With a trusted origin, PAT/`gho_`/`ghu_` use `/user`, `ghs_` uses `/installation/repositories`, and `ghr_` remains unverified because exchange would rotate it.
- **Slack** (`slack-token`): HTTP POST to `https://slack.com/api/auth.test` with `Bearer` token. Returns team/user metadata on success.

## 2. Verifier Classification

All 65 detectors are classified by verification feasibility. **All 54 implementations listed in Tiers 1–3 are registered, but nine implementations require trusted issuer, region, or companion context rather than providing a direct-live capability.**

### Tier 1 --- Easy (Simple API call, single credential, no extra context)

These detectors can be verified with a single HTTP request using only the detected secret as authentication. This is the highest-value, lowest-effort category.

| # | Detector ID | API Endpoint | Method | Auth Header | Complexity | Priority | Notes |
|---|-------------|-------------|--------|-------------|------------|----------|-------|
| 1 | `github-token` | Trusted GitHub.com/GHES `/user` | GET | `Bearer {token}` | Context required | P0 | GitHub.com and GHES share token formats; current production registration has no trusted origin and returns `unverified` without a request |
| 2 | `slack-token` | `https://slack.com/api/auth.test` | POST | `Bearer {token}` | Easy | P0 | Returns team/user metadata on success |
| 3 | `openai-api-key` | `https://api.openai.com/v1/models` | GET | `Bearer {token}` | Easy | P0 | Returns model list; 401 if invalid |
| 4 | `anthropic-api-key` | `https://api.anthropic.com/v1/models` | GET | `x-api-key: {token}` | Easy | P0 | Requires `anthropic-version` header |
| 5 | `gitlab-pat` | Operator-trusted GitLab.com/self-managed `/api/v4/user` | GET | `PRIVATE-TOKEN: {token}` | Context required | P0 | Repository content never chooses the origin; without explicit trust the verifier makes no request and returns `unverified`. Only the `glpat_` subtype supports this safe identity probe |
| 6 | `sendgrid-api-key` | `https://api.sendgrid.com/v3/scopes` | GET | `Bearer {token}` | Easy | P0 | Needs no specific scope, so a restricted-permission key is never misread as revoked; 401 = invalid, other unexpected statuses fall through to a verify error rather than a false negative |
| 7 | `digitalocean-token` | `https://api.digitalocean.com/v2/account` | GET | `Bearer {token}` | Easy | P0 | Returns account info |
| 8 | `cloudflare-api-token` | `https://api.cloudflare.com/client/v4/user/tokens/verify` | GET | `Bearer {token}` | Easy | P0 | Dedicated verify endpoint |
| 9 | `newrelic-api-key` | US/EU NerdGraph `/graphql` | POST (read-only query) | `Api-Key: {token}` | Regional fallback | P0 | `requestContext { userId }`; inactive only when every documented region returns 401; 403 is inconclusive |
| 10 | `heroku-api-key` | `https://api.heroku.com/account` | GET | `Bearer {token}` | Easy | P0 | Requires `Accept: application/vnd.heroku+json; version=3` |
| 11 | `notion-token` | `https://api.notion.com/v1/users/me` | GET | `Bearer {token}` | Easy | P0 | Requires `Notion-Version` header |
| 12 | `telegram-bot-token` | `https://api.telegram.org/bot{token}/getMe` | GET | Token in URL path | Easy | P0 | Token is part of URL, not header |
| 13 | `discord-bot-token` | `https://discord.com/api/v10/users/@me` | GET | `Bot {token}` | Easy | P0 | Returns bot user info |
| 14 | `sentry-token` | `https://sentry.io/api/0/` | GET | `Bearer {token}` | Easy | P1 | Returns auth info |
| 15 | `pagerduty-api-key` | `https://api.pagerduty.com/users/me` | GET | `Authorization: Token token={key}` | Easy | P1 | Custom auth format |
| 16 | `vercel-token` | `https://api.vercel.com/v2/user` | GET | `Bearer {token}` | Easy | P1 | Returns user info |
| 17 | `linear-api-key` | `https://api.linear.app/graphql` | POST | `Bearer {token}` | Easy | P1 | GraphQL query `{ viewer { id } }` |
| 18 | `circleci-token` | `https://circleci.com/api/v2/me` | GET | `Circle-Token: {token}` | Easy | P1 | Returns user info |
| 19 | `npm-token` | `https://registry.npmjs.org/-/npm/v1/user` | GET | `Bearer {token}` | Easy | P1 | Returns user profile |
| 20 | `huggingface-token` | `https://huggingface.co/api/whoami-v2` | GET | `Bearer {token}` | Easy | P1 | Returns user/org info |
| 21 | `airtable-pat` | `https://api.airtable.com/v0/meta/whoami` | GET | `Bearer {token}` | Easy | P1 | Dedicated whoami endpoint |
| 22 | `snyk-api-key` | Trusted regional/private `/rest/self` | GET | `Authorization: token {key}` | Context required | P1 | Snyk API origins are region/deployment-specific; current production registration returns `unverified` without a trusted origin |
| 23 | `figma-pat` | `https://api.figma.com/v1/me` | GET | `X-FIGMA-TOKEN: {token}` | Easy | P1 | Returns user info |
| 24 | `postmark-server-token` | `https://api.postmarkapp.com/server` | GET | `X-Postmark-Server-Token: {token}` | Easy | P1 | Returns server info |
| 25 | `grafana-api-key` | Issuing instance `/api/access-control/user/permissions` | GET | `Bearer {token}` | Context required | P1 | Explicit `--grafana-instance-url` only; no trusted URL means no request and `unverified`; repository-provided URLs are never trusted |
| 26 | `doppler-token` | `https://api.doppler.com/v3/me` | GET | `Bearer {token}` | Easy | P1 | Returns user/workplace info |
| 27 | `sonarcloud-token` | `https://sonarcloud.io/api/authentication/validate` | GET | Basic `{token}:` | Easy | P2 | Dedicated validate endpoint; Basic auth with token as username |
| 28 | `pypi-api-token` | `https://upload.pypi.org/legacy/` | POST | Basic `__token__:{token}` | Easy | P2 | Check via upload endpoint returns 400 (active) vs 403 (invalid) |
| 29 | `deepseek-api-key` | `https://api.deepseek.com/models` | GET | `Bearer {token}` | Easy | P2 | Returns model list; 401 if invalid |
| 30 | `launchdarkly-sdk-key` | `https://app.launchdarkly.com/api/v2/caller-identity` | GET | `Authorization: {key}` | Easy | P2 | Returns caller identity |

**Total Tier 1: 30 implementations — 26 direct-live and 4 context-required (`github-token`, `gitlab-pat`, `grafana-api-key`, `snyk-api-key`)**

### Tier 2 --- Medium (Needs extra context, specific auth flow, or domain extraction)

These require either extracting additional information from the finding context (e.g., a domain name, workspace slug), using a non-standard authentication flow, or making multiple API calls.

| # | Detector ID | API Endpoint | Method | Auth | Complexity | Priority | Notes |
|---|-------------|-------------|--------|------|------------|----------|-------|
| 1 | `aws-access-key-id` | AWS STS `GetCallerIdentity` | SDK | HMAC-signed | Medium | P0 | Needs both Access Key ID (`Raw`) + Secret Access Key (`RawV2`) |
| 2 | `stripe-api-key-live` | `https://api.stripe.com/v1/charges?limit=1` | GET | Basic `{key}:` | Medium | P0 | Live key -- verification must be read-only; use minimal-scope endpoint |
| 3 | `stripe-api-key-test` | `https://api.stripe.com/v1/charges?limit=1` | GET | Basic `{key}:` | Medium | P1 | Test key -- lower risk but same flow as live |
| 4 | `twilio-api-key` | Trusted regional Twilio origin + Accounts probe | GET | Basic `{apiKeySID}:{apiKeySecret}` | Context required | P1 | `Raw` is the opaque value from an explicit API Key Secret assignment, paired one-to-one with a nearby explicitly assigned non-secret `SK...` Key SID in the same logical block. `ExtraData` contains only that `api_key_sid` and an optional nearby `account_sid`; bare SIDs are not findings. Production lacks trusted regional-origin wiring and makes no request. Accounts/Keys permissions differ for Main, Standard and Restricted keys, so `403` is inconclusive; only `401` on the selected region is inactive |
| 5 | `mailgun-api-key` | `https://api.mailgun.net/v3/domains`, retrying `https://api.eu.mailgun.net/v3/domains` | GET | Basic `api:{key}` | Medium | P1 | Mailgun keys carry no region marker; the US host is probed first and the EU host is retried only if US reports the key inactive, so a live EU-only key is never misreported as dead |
| 6 | `shopify-access-token` | Trusted store origin + `/admin/api/2026-07/graphql.json` | POST | `X-Shopify-Access-Token: {token}` | Context required | P1 | Uses a read-only `shop { name }` identity query with strict JSON/GraphQL response validation. Finding-controlled domains are ignored; production has no trusted-store configuration and therefore makes no request. Only `401` on the operator-selected store is inactive |
| 7 | `okta-api-token` | `https://{domain}/api/v1/users/me` | GET | `SSWS {token}` | Medium | P1 | Domain is captured by the detector from a co-located org domain in `ExtraData["domain"]`; without it, the result is `unverified` (never a false invalid) |
| 8 | `databricks-token` | `https://{workspace-host}/api/2.0/preview/scim/v2/Me` | GET | `Bearer {token}` | Medium | P1 | Workspace host captured by the detector in `ExtraData["host"]` (a Databricks PAT only authenticates against its own workspace host); without it, the result is `unverified` |
| 9 | `github-oauth-token` | Trusted GitHub.com/GHES subtype-specific identity endpoint | GET | `Bearer {token}` | Context required | P1 | `gho_`/`ghu_` → `/user`; `ghs_` → `/installation/repositories`; `ghr_` is never exchanged because verification would rotate it; current production registration returns `unverified` without a trusted origin |
| 10 | `auth0-management-token` | Operator-trusted Auth0 tenant/custom `/api/v2/clients` | GET | `Bearer {token}` | Context required | P2 | JWT claims are untrusted scanner input and never choose the request origin; without explicit operator trust the verifier makes no request and returns `unverified` |
| 11 | `datadog-api-key` | Trusted Datadog site `/api/v1/validate` | GET | `DD-API-KEY: {key}` | Context required | P2 | Keys are site-bound across official regions; current production registration returns `unverified` without a trusted site |
| 12 | `terraform-cloud-token` | `https://app.terraform.io/api/v2/account/details` | GET | `Bearer {token}` | Medium | P2 | Standard Bearer auth; some tokens may be for Terraform Enterprise (custom URL) |
| 13 | `supabase-service-key` | `https://api.supabase.com/v1/projects` | GET | `Bearer {token}` | Medium | P2 | Detects a Management API personal access token (`sbp_`), despite the stable legacy ID; fixed provider host, `401` inactive, `403` inconclusive |
| 14 | `rubygems-api-key` | `https://rubygems.org/api/v1/api_key.json` | GET | `Authorization: {key}` | Medium | P2 | Returns key metadata |
| 15 | `bitbucket-app-password` | `https://api.bitbucket.org/2.0/user` | GET | Basic `{username}:{app-password}` | Medium | P2 | Username captured by the detector in `ExtraData["username"]` |
| 16 | `dockerhub-pat` | `https://hub.docker.com/v2/user/` | GET | `Bearer {token}` | Medium | P2 | Docker Hub PATs authenticate the v2 API directly; no login/JWT-exchange step and no username needed |
| 17 | `teams-webhook` | `POST {webhookURL}` | POST | None (URL is the credential) | Medium | P1 | Sends minimal payload; 400 treated as active (valid URL, empty payload rejected). Live probe — no real message content posted. |
| 18 | `infura-api-key` | `https://mainnet.infura.io/v3/{token}` | POST | Token in URL path | Medium | P1 | JSON-RPC `web3_clientVersion` call. Consumes a small amount of API quota. |

**Total Tier 2: 18 implementations — 13 direct-live and 5 context-required (`twilio-api-key`, `shopify-access-token`, `github-oauth-token`, `auth0-management-token`, `datadog-api-key`)**

> **Note:** `hashicorp-vault-token` was previously listed in this tier (Tier 2 P2) but has no verifier implementation. It has been moved to Tier 4 (no verifier). See section 2 Tier 4 for rationale. `coinbase-api-key` was previously listed here but is a format-only (Tier 3) check — see below.

### Tier 3 --- Format-Only (Implemented; validates structure but cannot confirm liveness)

These detectors have verifier implementations that perform structural/format validation. A live network check is either impractical (requires secondary credentials or non-HTTP protocol) or was deferred.

| # | Detector ID | Verifier | Approach | Notes |
|---|-------------|----------|----------|-------|
| 1 | `azure-storage-key` | `internal/verifier/azure` (`StorageVerifier`) | Parses `AccountName`/`AccountKey` from connection string; validates AccountKey is valid base64 | Live check requires HMAC-SHA256 signed Azure REST API call |
| 2 | `azure-entra-secret` | `internal/verifier/azure` (`EntraVerifier`) | Regex format check (34-40 char alphanum) | Live check requires OAuth2 client_credentials flow with tenant ID + client ID |
| 3 | `gcp-service-account` | `internal/verifier/gcp` | JSON structure validation (type, project_id, private_key_id, client_email) | Live check requires JWT assertion to Google OAuth2 endpoint |
| 4 | `snowflake-credentials` | `internal/verifier/snowflake` | Non-empty credentials check only | Live check requires direct database connection (JDBC/ODBC) |
| 5 | `rabbitmq-connection-string` | `internal/verifier/rabbitmq` | AMQP URL scheme + user + host validation | Live check requires network access to the broker |
| 6 | `coinbase-api-key` | `internal/verifier/coinbase` | Key character-set/length format check | Coinbase's v2 API authenticates with HMAC-SHA256 request signing using the key's paired secret, which the detector captures as an independent, unpaired finding — never attempts a live call, and always returns `unverified` (never a false active/inactive) |

**Total Tier 3 (Format-Only): 6 verifiers**

### Tier 4 --- No Verifier Implemented

These 11 detectors currently have no verifier. The reasons range from "no public API" to "side effects on verification" to "provider/issuer cannot be determined safely."

| # | Detector ID | Reason / Status |
|---|-------------|-----------------|
| 1 | `private-key` | No remote verification endpoint. RSA/SSH/DSA/EC/PGP keys are validated by the target system, not via a public API. |
| 2 | `generic-api-key` | Catches generic patterns (`api_key=`, `apikey:`, etc.). No way to determine the owning service, so no API to call. |
| 3 | `database-connection-string` | PostgreSQL, MySQL, MSSQL, MongoDB connection strings. Verification requires direct DB connection — intrusive and may trigger security alerts. |
| 4 | `redis-connection-string` | Redis connection URIs (`redis://`). Verification requires direct TCP connection to a typically internal host. |
| 5 | `ftp-credentials` | FTP/SFTP URIs with embedded credentials. Verification requires direct connection to potentially internal FTP servers. |
| 6 | `ldap-credentials` | LDAP bind credentials (`ldap://`). Verification requires direct connection to an internal LDAP directory. |
| 7 | `slack-webhook` | Webhook URLs (`https://hooks.slack.com/services/...`). Any call would POST a message to a real channel (side effect). Read-only verification is not possible. |
| 8 | `discord-webhook-url` | Discord incoming-webhook URLs. Any call would POST a message to a real channel (side effect). Read-only verification is not possible. |
| 9 | `jwt` | JSON Web Tokens. Cannot verify the signature without the signing key. Can only check expiry and structural validity — no live state can be confirmed. Planned. |
| 10 | `hashicorp-vault-token` | Vault tokens. Live check requires the Vault server address extracted from context, which is typically not available in a static finding. Planned. |
| 11 | `structured-config-secret` | Strong field context identifies a secret role, but the provider and issuer cannot be determined safely. |

**Total Tier 4: 11 detectors (no verifier)**

### Verified Tier Summary

| Tier | Count | Description |
|------|-------|-------------|
| Direct live | 39 | Safe live request is available in the normal production path |
| Requires trusted issuer/region/companion context | 9 | Registered, but a bare finding cannot safely make a live request |
| Tier 3 — Format-Only | 6 | Structural validation; no network call |
| Tier 4 — No Verifier | 11 | Not implemented |
| **Total Detectors** | **65** | |
| **Registered verifier implementations** | **54** | Direct-live: 39 · context-required: 9 · format-only: 6 |

> **Registry coverage:** 54/65 = **83.1%**. **Direct-live capability:** 39/65 = **60.0%**.

**Notes:**
- `teams-webhook` (`internal/verifier/teams`): Live HTTP POST probe. A 400 response (valid URL but empty payload rejected) is treated as active. This is a deliberate non-destructive probe — no readable message is posted.
- `infura-api-key` (`internal/verifier/infura`): Live JSON-RPC POST (`web3_clientVersion`). This does consume a small amount of API quota; the call is read-only and non-destructive.
- `rabbitmq-connection-string` (`internal/verifier/rabbitmq`): Format-only (Tier 3). AMQP URL structure validated; no network connection attempted.
- `coinbase-api-key` (`internal/verifier/coinbase`): Format-only (Tier 3). Key shape validated only; never attempts a live call since Coinbase's HMAC-signed API requires the paired secret, which the detector cannot reliably supply.

## 3. Implementation Roadmap (COMPLETED)

All 5 sprints have been completed. Two additional verifiers (`teams-webhook`, `infura-api-key`) were added outside the original roadmap. Actual verification coverage as of 2026-05-22: **54/63 = 85.7%**.

> **Roadmap note corrections (2026-05-22):** The original roadmap counted 64 detectors (correct count is 63) and included `hashicorp-vault-token` in Sprint 4 and `jwt` in Sprint 5. Neither verifier was implemented. Both remain in Tier 4 (no verifier). The sprint descriptions below have been updated to reflect what was actually built.

### Sprints 1–5 Summary

| Sprint | New Verifiers | Cumulative Coverage (of 63) | Notes |
|--------|--------------|------------------------------|-------|
| Sprint 1 (Tier 1 P0) | 8 | 11/63 (17.5%) | github, slack, openai, anthropic, gitlab, sendgrid, digitalocean, cloudflare, telegram, discord, newrelic |
| Sprint 2 (Tier 1 P1) | 11 | 22/63 (34.9%) | heroku, notion, sentry, pagerduty, vercel, linear, circleci, npm, huggingface, airtable |
| Sprint 3 (Tier 1 P2 + Tier 2 P1) | 11 | 33/63 (52.4%) | snyk, figma, postmark, grafana, doppler, sonarcloud, deepseek, launchdarkly, stripe×2, twilio |
| Sprint 4 (Tier 2) | 10 | 43/63 (68.3%) | mailgun, shopify, okta, databricks, github-oauth, pypi, auth0, coinbase, datadog, terraform |
| Sprint 5 (Tier 2 + Tier 3) | 9 | 52/63 (82.5%) | supabase, rubygems, bitbucket, dockerhub, azure-storage, azure-entra, gcp, snowflake, rabbitmq |
| Post-roadmap additions | 2 | 54/63 (85.7%) | teams-webhook, infura-api-key (live probes added in fix/wire-custom-rules-and-inline-ignore) |
| **Total** | **51** | **54/63 (85.7%)** | |

> **Historical snapshot:** the sprint table above reflects the state as of 2026-05-22, before the `discord-webhook-url` and `structured-config-secret` detectors were added and before capability was separated from registry presence. **Current totals are 65 detectors / 54 registered implementations = 83.1% registry coverage, with 39 direct-live capabilities** (section 1); the sprint-by-sprint history is preserved here unchanged for traceability.

## 4. Security Considerations

### Rate Limiting

Every verifier MUST implement per-provider rate limiting to avoid triggering abuse detection or account lockouts.

| Provider Category | Recommended Rate Limit | Rationale |
|-------------------|----------------------|-----------|
| AI Providers (OpenAI, Anthropic, DeepSeek) | 5 req/min | API usage may incur costs to the key owner |
| Source Control (GitHub, GitLab, Bitbucket) | 10 req/min | GitHub allows 5000/hr authenticated, but be conservative |
| Communication (Slack, Discord, Telegram) | 5 req/min | Avoid triggering spam detection |
| Cloud Providers (AWS, GCP, Azure) | 5 req/min | STS/IAM calls have low limits |
| CI/CD (CircleCI, Vercel, Terraform) | 5 req/min | Typically lower rate limits |
| All Others | 5 req/min | Default conservative limit |

Implementation: Use `golang.org/x/time/rate` (already a dependency) with a per-verifier `rate.Limiter` instance.

### Credential Safety

- **NEVER** log, print, or persist raw secret values during verification. This is enforced by the `Verifier` interface contract.
- Redact secrets in all error messages. Use `slog` structured logging with only metadata fields.
- HTTP client must not follow redirects that could leak the `Authorization` header to third-party domains.
- Set a custom `User-Agent: leakwatch-verifier` on all requests for transparency.

### Timeout Handling

- All verifier HTTP requests MUST respect the `context.Context` deadline.
- Default per-finding verification-operation timeout: **10 seconds**, including bounded provider-region fallback.
- If the verification API is unreachable or times out, return `StatusVerifyError` (not `StatusVerifiedInactive`). A network failure does not mean the secret is invalid.
- Implement exponential backoff for transient failures (429, 503) with a maximum of 2 retries.

### Verification API Downtime

When a provider's API is unavailable:

1. Return `finding.StatusVerifyError` with a descriptive message.
2. The finding is reported with `unverified` status -- it is NOT suppressed.
3. Log the error at `slog.Warn` level for operational visibility.
4. Do **not** cache negative results from API errors. Only cache definitive `active` or `inactive` results.

### Network Security

- All verification requests MUST use HTTPS. HTTP endpoints MUST be rejected.
- TLS certificate validation MUST NOT be disabled.
- Consider implementing a configurable HTTP proxy for environments where direct internet access is not available.
- DNS resolution should use the system resolver; do not hardcode IP addresses.

### Minimal-Privilege Verification

- Always use the **least-privilege** API endpoint for verification. Prefer read-only endpoints that return minimal data.
- Never call endpoints that modify state (create, update, delete).
- For Stripe: use `GET /v1/charges?limit=1`, not `POST /v1/charges`.
- For webhook URLs (Slack, Teams): do **not** verify, as any call would post a message.

## 5. Implementation Guidelines

### Verifier Template

Each new verifier should follow this structure:

```go
package <provider>

import (
    "context"
    "fmt"
    "log/slog"
    "net/http"

    "github.com/HodeTech/leakwatch/internal/detector"
    "github.com/HodeTech/leakwatch/internal/verifier"
    "github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "<detector-id>"

type Verifier struct {
    apiURL     string
    httpClient *http.Client
}

func init() {
    verifier.Register(&Verifier{})
}

func (v *Verifier) Type() string { return detectorID }

func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
    // 1. Extract and validate the secret from raw.Raw
    // 2. Build the HTTP request with proper auth header
    // 3. Execute with context-aware HTTP client
    // 4. Interpret response: 200 = active, 401/403 = inactive, other = error
    // 5. Return VerificationResult with metadata in ExtraData
}
```

### Testing Requirements

- Each verifier MUST have a corresponding `*_test.go` with table-driven tests.
- Use `httptest.NewServer` to mock provider APIs.
- Test cases must cover: active token, inactive/revoked token, network error, timeout, malformed response, empty input.
- Target: **95% code coverage** for all verifier packages (consistent with detector coverage requirement).

### Verifier Registration

New verifiers are registered at compile time. After creating the verifier package, add the blank import to `cmd/imports.go`:

```go
import (
    _ "github.com/HodeTech/leakwatch/internal/verifier/<provider>"
)
```

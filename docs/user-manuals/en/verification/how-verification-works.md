---
title: "How Verification Works"
description: "How Leakwatch confirms whether a detected secret is still active, which verification modes it uses, and how to configure or disable verification."
---

# How Verification Works

Finding a secret in a codebase is only half the story. A key that was rotated six months ago is noise; a key that is still live is an active incident. Verification is the step that draws that line — it takes each detected finding and, where possible, confirms whether the secret is currently valid at the provider.

## From detection to verification

After the scan engine collects findings, the verifier pool picks them up. Each finding carries a `detector_id`; Leakwatch looks up whether a verifier is registered for that ID:

- If a verifier exists, it runs and returns a status.
- If no verifier is registered for that detector type, the finding passes through unchanged with status `unverified`.

## Three verification modes

Not all secrets can be verified the same way. Leakwatch distinguishes direct live checks, checks that require trusted or companion context, and offline format validation. Registry presence is therefore not treated as proof of live capability.

### Live API verification

For 41 detector types, Leakwatch can make a **controlled, non-destructive provider check** in the normal production path — for example, calling `sts:GetCallerIdentity` for AWS keys or a fixed provider identity endpoint for OpenAI keys. The call uses only the minimum endpoint required to confirm identity; it never modifies data or creates resources, though it may consume provider quota.

If the provider returns a contract-valid success response, the finding is marked `verified_active`. A finding is marked `verified_inactive` only when the provider response is definitive under that verifier's contract. Permission denial and ambiguous responses remain `verify_error`; for example, SendGrid treats only HTTP `401` as inactive, while `403` remains inconclusive.

### Trusted or companion context required

Seven registered implementations cannot safely make a live request from a bare detector finding. Grafana, GitHub/GHES, Datadog, and Snyk require a trusted issuer/site/API origin; Twilio requires the Account SID and paired API Key Secret; Shopify requires the issuing store domain. Without that context Leakwatch sends no request and returns `unverified`, rather than guessing an issuer or misreporting a real credential as inactive.

### Format validation only

For six credential types, no safe live check exists — the provider has no anonymous identity endpoint, a real call would have side effects, or (for `coinbase-api-key`) the live API requires HMAC request signing with a paired secret that cannot be reliably associated with the key. For these, Leakwatch validates the structure of the credential without making any network request:

| Detector ID | What is validated |
|-------------|------------------|
| `gcp-service-account` | JSON structure — `type`, `project_id`, `private_key_id`, `client_email` fields present |
| `rabbitmq-connection-string` | AMQP URL parsed successfully |
| `snowflake-credentials` | Format check only — a valid format proves nothing, result is always `unverified` |
| `azure-storage-key` | Format check |
| `azure-entra-secret` | Format check |
| `coinbase-api-key` | Character-set and length check |

:::note
Even when the format check passes, the result remains `unverified`. A structurally valid credential may be expired or revoked. These findings always require manual triage.
:::

## Verification statuses

Every finding in Leakwatch output carries one of four statuses:

| Status | Meaning | Recommended action |
|--------|---------|-------------------|
| `verified_active` | The secret was confirmed live by the provider. | Treat as an active incident. Rotate immediately. |
| `verified_inactive` | The provider rejected the credential. | Likely already rotated. Review context and close. |
| `unverified` | No verifier exists, required context is absent, a format-only verifier cannot prove liveness, or verification was disabled. | Triage manually; context determines risk. |
| `verify_error` | The verifier ran but encountered a network error, timeout, or unexpected response. | Treat as potentially active. Retry or triage manually. |

## The verification engine

Verification runs in a dedicated concurrent worker pool, isolated from the scan worker pool. The defaults are conservative to avoid triggering provider rate limits:

| Setting | Default | Config key |
|---------|---------|-----------|
| Worker count | 4 | `verification.concurrency` |
| Global rate limit | 10 requests/second | `verification.rate-limit` |
| Per-request timeout | 10 s | `verification.timeout` |

All three values are tunable under the `verification:` block in `.leakwatch.yaml`:

```yaml
verification:
  enabled: true
  concurrency: 4
  rate-limit: 10.0   # requests per second (global)
  timeout: 10s
```

:::tip
If you are scanning a repository that triggers hundreds of findings, consider lowering `rate-limit` to 5 or enabling `--only-verified` to keep the verified-active set small and actionable.
:::

## Controlling verification at the command line

**Disable verification entirely** with `--no-verify` (or set `verification.enabled: false` in config). Every finding passes through as `unverified`. Use this for offline or air-gapped environments, or when you want the fastest possible scan without touching any provider API.

```bash
leakwatch scan fs . --no-verify
```

**Show only confirmed-live secrets** with `--only-verified`. Everything that is not `verified_active` is dropped from the output. This is the fastest way to triage a large result set — you see only the keys you must act on now.

```bash
leakwatch scan git . --only-verified
```

:::warn
`--only-verified` silently drops `unverified` and `verify_error` findings. Do not use it as your sole filter in a compliance context — some credential types (JWTs, generic API keys, private keys) can never be verified and would always be excluded.
:::

## Secret safety

Verification is designed so that the raw secret value never leaves the process boundary in an unsafe way:

- Verifiers pass the secret directly to the provider's HTTP endpoint over TLS — it is never written to disk, emitted to a log, or cached between runs.
- A verifier that fails to initialise or encounters a panic is caught by the engine, which marks the finding `verify_error` and continues rather than crashing the scan.

## See also

- [Verification Coverage](#/verification/verification-coverage) — which detector types are live-verified, format-validated, or not verifiable at all.
- [Configuration: Config File](#/configuration/config-file) — full reference for the `verification:` block.
- [Output Formats](#/output/output-formats) — how the verification status appears in JSON, SARIF, CSV, and table output.

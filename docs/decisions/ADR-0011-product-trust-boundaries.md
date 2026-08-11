# ADR-0011: Product Enhancement Trust Boundaries

- **Status:** Accepted
- **Date:** 2026-08-11
- **Decision Makers:** Project team

## Context

The post-review product backlog mixes low-risk improvements with features that can suppress findings, transmit credentials, or publish artifacts externally. Treating every unchecked roadmap item as equivalent would encourage unsafe implementation merely to mark it complete. The product needs explicit shipped/experimental/planned states and acceptance boundaries.

## Decision

The current status is:

| Capability | Status | Contract |
|---|---|---|
| Slack text-file attachments | **Shipped** | Explicit `--include-files`; `files:read`; Slack-owned HTTPS only; shared limiter; bounded size/retry; text/NUL filtering; file-ID deduplication; terminal errors fail the source. |
| GitHub/GitLab scope and expiry metadata | **Shipped** | Best-effort, schema-validated metadata only after an authoritative active proof; malformed or unavailable enrichment never changes active/inactive evidence. |
| VSIX build and icon | **Shipped** | Lockfile-pinned local package command and CI artifact; the VSIX contains only the bundled runtime, license/readme/changelog, manifest, and 256×256 icon. |
| Visual Studio Marketplace publication | **Experimental** | Manual workflow only, explicit boolean input, protected `vscode-marketplace` environment, one reviewed VSIX artifact, and environment-scoped `VSCE_PAT`. No automatic tag publication. |
| Provider contract freshness audit | **Shipped** | Primary references and review dates in the capability manifest; weekly 180-day freshness gate; synthetic adversarial tests remain mandatory. |
| Baseline/snapshot suppression | **Planned** | Not exposed until the threat model and versioned format below are implemented and tested. |
| Coinbase legacy live HMAC verification | **Planned** | Remains format-only until key/secret correlation is assignment-aware, unambiguous, secret-safe, and backed by a safe read-only provider contract. |
| Live provider canaries | **Planned** | No credentials in default CI; provider-specific, protected, explicit opt-in only after the controls in the provider-audit standard are satisfied. |

### Baseline threat model and required design

A baseline can hide a real credential, so a plain detector/path allowlist or an unkeyed hash is not acceptable. The future implementation must:

1. use a versioned, strict schema and reject unknown versions/fields, duplicate identities, malformed paths, and oversized inputs;
2. store no raw or redacted credential material;
3. identify entries with `HMAC-SHA-256(key, "leakwatch-baseline/v1" || length-prefixed detector ID || length-prefixed normalized source identity || length-prefixed raw credential)` using an external organization-controlled, high-entropy key that is never written to the baseline; the canonical length prefixes prevent concatenation ambiguity;
4. fail closed when the key is absent, malformed, or unavailable and never silently treat an unreadable baseline as empty;
5. make creation/update an explicit user command, write atomically with restrictive permissions, and never auto-approve changes during a scan;
6. apply suppression before live verification so an accepted legacy secret is not transmitted merely because it is baselined, while keeping suppressed counts visible in the summary; and
7. ship adversarial tests for tampering, replay to another path/detector, low-entropy offline guessing, symlink/output attacks, merge conflicts, and secret leakage in every formatter/log/error.

Repository write access alone must not let an attacker create a valid suppression entry; the external HMAC key is the second trust boundary. Teams that cannot protect such a key must use existing explicit ignore mechanisms with normal code review rather than baseline mode.

## Alternatives Considered

### Ship a plaintext or SHA-256 baseline immediately

Rejected. It either stores sensitive material or permits offline guessing of low-entropy credentials, and repository writers can suppress new findings without a second trust boundary.

### Automatically publish every extension tag

Rejected. Marketplace publication is an external, difficult-to-reverse action. A reviewable artifact and protected manual promotion keep build and publication separate.

### Add shared live credentials to scheduled CI

Rejected. It expands secret distribution and may trigger billing, alerts, mutations, or provider abuse controls. Contract tests plus dated official-document audits are the safe default.

### Guess Coinbase key/secret pairs by proximity

Rejected. Ambiguous pairing can send the wrong secret and turn an authentication rejection into a false inactive result. Format-only is the truthful current capability.

## Consequences

Low-risk enhancements ship with executable acceptance tests, while suppression, live credentials, and external publication retain explicit gates. Some roadmap items remain planned; this is deliberate product truthfulness, not an implementation claim. Future work must amend this ADR when it changes any trust boundary or status.

## Related Documents

- [Provider Verification Contract Audits](../standards/05-PROVIDER-CONTRACT-AUDITS.md)
- [ADR-0009: GitHub Marketplace Action](ADR-0009-github-marketplace-action.md)
- [Verification Coverage](../user-manuals/en/verification/verification-coverage.md)

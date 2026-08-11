# Provider Verification Contract Audits

Provider APIs change independently of Leakwatch. A verifier may therefore keep compiling while its endpoint, region model, status semantics, response schema, or credential type becomes stale. This standard makes reviewed contracts explicit and time-bounded without pretending that every registered verifier has already received a current audit.

## Canonical evidence

`internal/meta.VerificationCapability` is the machine-readable source of truth. A completed audit must set both:

- `LastContractReviewedAt`, using `YYYY-MM-DD`; and
- one or more `ContractReferenceURLs` that point to primary provider documentation.

An empty date means **not audited under this process**. It must never be presented as a completed review. A date without primary references, references without a date, non-HTTPS or non-allowlisted provider hosts, future dates, and reviewed contracts older than 180 days fail the metadata contract tests.

## Audit procedure

For every audited verifier:

1. Confirm the credential class and supported token subtypes.
2. Confirm the endpoint, HTTP method, authentication scheme, provider regions, and any trusted issuer/origin requirement.
3. Confirm the exact evidence that means active, inactive, or verification error. Permission failures and malformed success responses must remain fail-conservative.
4. Confirm bounded request count, redirects, response size/content type, cancellation, rate limiting, and secret-safe errors/logs.
5. Update the verifier's adversarial response matrix before advancing the review date.
6. Record only primary provider documentation URLs in the capability manifest.

The weekly `provider-contract-audit.yml` workflow runs the freshness gate and a bounded live documentation check. Every recorded URL must resolve with a 2xx response on an allowlisted official provider host; a recorded fragment must exist in the returned page. Redirects are bounded and may only remain within the official-host allowlist. Its purpose is to make audit due dates and dead/misdirected evidence visible and blocking; changing only the date without reviewing the references, implementation, and tests violates this standard.

## Live canaries

Default CI must never contain or transmit real credentials. Provider canaries remain **planned** until a provider-specific design proves all of the following:

- explicit opt-in in a protected environment;
- a dedicated least-privilege test credential owned by the project;
- no billing, mutation, notification, rotation, or third-party alert side effect;
- secret masking in every process, error, log, artifact, and cache boundary;
- bounded requests, timeout, rate limit, and immediate revocation procedure; and
- a documented provider owner and audit trail.

Synthetic `httptest` contract matrices remain the required CI mechanism. A live canary may supplement them but can never replace them.

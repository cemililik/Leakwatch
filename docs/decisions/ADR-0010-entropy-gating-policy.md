# ADR-0010: Entropy Gating Policy

- **Status:** Accepted
- **Date:** 2026-08-11
- **Decision Makers:** Project team
- **Supersedes:** The tertiary entropy policy in [ADR-0005](ADR-0005-pattern-matching.md)

## Context

ADR-0005 originally made engine-level entropy display-only and reserved threshold filtering for custom rules. Leakwatch now has a bounded engine policy for heuristic built-in findings as well. Leaving the accepted decision unchanged would make the ADR chain contradict the executable contract and encourage future regressions.

Entropy is useful for arbitrary credential-like assignments, but it is not reliable evidence for structurally identified provider credentials. Applying one global threshold to every detector would suppress legitimate low-entropy secrets. Conversely, calculating a score without allowing explicitly heuristic detectors to use it leaves a documented false-positive control ineffective.

## Decision

When `detection.entropy.enabled` is true, the engine calculates and attaches Shannon entropy to every non-empty finding. The configured `detection.entropy.threshold` is a suppression gate only when all of these conditions hold:

1. The detector explicitly implements the engine's `EntropyBased` contract and returns `true`.
2. If the detector also implements `EntropyGated`, that per-finding policy returns `true`.
3. The finding's entropy is below the configured threshold.

Built-in structural provider findings never become ineligible merely because their entropy is low. The current built-in opt-in detector is `generic-api-key`; its explicit provider-context findings may bypass the threshold through `EntropyGated`, while ordinary heuristic assignments remain gated.

Custom YAML rules keep their independent per-rule `entropy` threshold. Their filtering contract is not replaced by the built-in detector gate.

The implementation in `internal/engine/engine.go` and its executable tests are authoritative for the interface and ordering details. Current user-facing behavior is documented in the English user manual; translations and supplemental guides must preserve that contract.

## Alternatives Considered

### Keep entropy display-only for all built-in detectors

Rejected. This would preserve known high-noise heuristic matches and make the configured global threshold misleading.

### Gate every detector with the global threshold

Rejected. Entropy is not a validity signal for many provider-issued formats and would introduce false negatives.

### Maintain an engine-owned detector ID allowlist

Rejected. Optional detector interfaces keep the policy local, testable, and extensible without coupling the engine to registry names.

## Consequences

### Positive

- The global setting has a precise, executable effect on heuristic built-in findings.
- Structural credentials remain recall-safe regardless of entropy.
- Mixed detectors can refine the decision per finding.
- Documentation and tests can assert one stable opt-in contract.

### Negative

- New heuristic detectors must deliberately choose and test their entropy policy.
- Entropy calculations remain visible on findings even when they do not control eligibility.
- Custom rules and built-in detectors retain separate threshold mechanisms that documentation must distinguish.

## Related Decisions

- [ADR-0005: Pattern Matching Strategy](ADR-0005-pattern-matching.md) — Aho-Corasick and regex pipeline; entropy clause superseded here
- [ADR-0008: Concurrency Model](ADR-0008-concurrency-model.md) — worker execution model in which the gate runs

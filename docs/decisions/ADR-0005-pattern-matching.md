# ADR-0005: Pattern Matching Strategy — Aho-Corasick Hybrid

- **Status:** Amended by [ADR-0010](ADR-0010-entropy-gating-policy.md)
- **Date:** 2026-03-24
- **Decision Makers:** Project team

## Context

Secret scanning requires matching thousands of different patterns (regex) against potentially gigabytes of data. Go's RE2-based `regexp` package is 2-5x slower compared to Rust's regex crate. A naive approach of scanning the text repeatedly for each pattern is impractical.

## Decision

**Aho-Corasick-first hybrid strategy** has been selected:

1. **Primary:** Fixed keyword pre-filtering with the Aho-Corasick algorithm (single pass, O(n))
2. **Secondary:** Regex validation only on chunks where Aho-Corasick matches occur, and only for the matching detectors
3. **Tertiary:** Shannon entropy score attached to each finding for human review. At the engine level this is **display-only** — the engine never gates or suppresses findings based on the entropy value. Threshold gating is active only for custom rules (the `entropy:` field in a YAML rule definition). A global entropy gate for built-in detectors is planned but not yet implemented (see ROADMAP "Known Gaps & Follow-up Work").

### Rationale

- Aho-Corasick matches all patterns in a single pass — O(n) regardless of pattern count
- 90%+ of secret patterns start with fixed prefixes (`AKIA`, `ghp_`, `sk-live-`, `xoxb-`)
- Chunks with no matches (expected to be 90%+) are skipped without running any regex
- This approach practically eliminates Go's regex disadvantage
- CPU cache friendly — single pass over the text

### Library

`cloudflare/ahocorasick` — Implementation proven in Cloudflare production.

## Alternatives Considered

### Separate regex for each pattern (naive)

- **Pros:** Simple implementation
- **Cons:** O(n * m) complexity (n=text, m=pattern count), does not scale
- **Decision:** Rejected.

### Rust FFI for regex hot path

- **Pros:** Highest raw regex performance
- **Cons:** Requires CGO, cross-compilation becomes complex, increases maintenance burden
- **Decision:** Deferred. Will be evaluated in the future if the Aho-Corasick strategy proves insufficient.

### Hyperscan (Intel)

- **Pros:** SIMD-accelerated multi-pattern matching
- **Cons:** C library (requires CGO), Intel-specific SIMD, license restrictions
- **Decision:** Rejected. Platform dependency is unacceptable.

## Consequences

### Positive

- Regex workload reduced by 90%+
- Performance remains constant as pattern count grows (thousands of detectors can be added)
- Efficient CPU cache utilization
- Pure Go — no CGO required

### Negative

- Compiling the Aho-Corasick automaton requires additional startup time (negligible)
- Detectors without keywords (purely entropy-based) cannot benefit from Aho-Corasick pre-filtering

## Related Decisions

- [ADR-0001: Programming Language](ADR-0001-programming-language.md) — Go's regex weakness triggering this decision
- [ADR-0010: Entropy Gating Policy](ADR-0010-entropy-gating-policy.md) — amends the tertiary entropy policy; the Aho-Corasick and regex decisions remain active

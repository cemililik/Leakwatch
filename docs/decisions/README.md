# Architecture Decision Records (ADR)

This directory contains the architectural decisions for the Leakwatch project in [ADR (Architecture Decision Record)](https://adr.github.io/) format.

## What is an ADR?

An ADR is a short document that records the context, rationale, and consequences of an important decision made in software architecture. Its purpose is to answer the question "why did we make this decision?" in the future.

## Format

Each ADR follows the structure below:

- **Title:** `ADR-NNNN: <Decision Title>`
- **Status:** Proposed | **Accepted** | Superseded | Amended | Rejected | Deprecated
- **Context:** The situation and problem that led to the decision
- **Decision:** The decision made and its rationale
- **Alternatives Considered:** Options evaluated and reasons for rejection
- **Consequences:** Positive and negative impacts of the decision

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-0001](ADR-0001-programming-language.md) | Programming Language: Go | Accepted | 2026-03-24 |
| [ADR-0002](ADR-0002-cli-frame.md) | CLI Framework: Cobra + Viper | Accepted | 2026-03-24 |
| [ADR-0003](ADR-0003-git-library.md) | Git Library: go-git | Accepted | 2026-03-24 |
| [ADR-0004](ADR-0004-plugin-architecture.md) | Plugin Architecture: Compile-Time | Accepted | 2026-03-24 |
| [ADR-0005](ADR-0005-pattern-matching.md) | Pattern Matching: Aho-Corasick Hybrid | Amended by ADR-0010 | 2026-03-24 |
| [ADR-0006](ADR-0006-container-library.md) | Container Library: go-containerregistry | Accepted | 2026-03-24 |
| [ADR-0007](ADR-0007-license.md) | License: MIT | Accepted | 2026-03-24 |
| [ADR-0008](ADR-0008-concurrency-model.md) | Concurrency: Worker Pool | Accepted | 2026-03-24 |
| [ADR-0009](ADR-0009-github-marketplace-action.md) | GitHub Marketplace Action: Location & Runtime | Accepted | 2026-05-24 |
| [ADR-0010](ADR-0010-entropy-gating-policy.md) | Entropy Gating Policy | Accepted | 2026-08-11 |
| [ADR-0011](ADR-0011-product-trust-boundaries.md) | Product Enhancement Trust Boundaries | Accepted | 2026-08-11 |

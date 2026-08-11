# Leakwatch - Documentation Standards

> **Document Version:** 2.0
> **Date:** 2026-08-11
> **Status:** Approved

---

## 1. General Principles

1. **Language:** English is the authoritative source language. The Turkish user manual is a reviewed translation that must preserve the English page set and product semantics. Code comments, logs, errors, architecture documents, standards, ADRs, and supplemental guides remain English.
2. **Format:** All documents are written in GitHub-Flavored Markdown (GFM) format.
3. **Encoding:** UTF-8, line endings LF (`\n`).
4. **Line length:** No mandatory line length limit in Markdown files; use natural paragraph flow.

---

## 2. Directory Structure

```
docs/
├── architecture/       # Architecture and technical design documents
│   ├── 01-COMPETITIVE-ANALYSIS.md
│   ├── 02-TECHNOLOGY-DECISIONS.md
│   └── 03-ARCHITECTURE.md
├── decisions/          # Architecture Decision Records (ADR)
│   ├── README.md       # ADR index and description
│   ├── ADR-0001-programming-language.md
│   ├── ADR-0002-cli-frame.md
│   └── ...
├── standards/          # Standards and rules
│   ├── 00-DOCUMENTATION-STANDARDS.md   (this document)
│   ├── 01-CODE-REVIEW-STANDARDS.md
│   ├── 02-RELEASE-STANDARDS.md
│   └── 04-DEVELOPMENT-STANDARDS.md
├── user-manuals/       # Canonical product behavior (EN source + TR translation)
│   ├── _meta.yaml      # Canonical page/language navigation contract
│   ├── en/             # Authoritative user-facing source
│   └── tr/             # Reviewed translation; same page set as EN
├── guides/             # Supplemental operational and implementation deep dives
│   ├── README.md        # Scope and canonical-source boundary
│   └── *.md             # Supplemental deep dives
└── 05-ROADMAP.md       # Roadmap (under root docs/)

site/js/manuals/        # Generated publication output; never edited by hand
├── _index.js           # Navigation bundle from _meta.yaml
├── en.js               # Compiled English manual
└── tr.js               # Compiled Turkish manual
```

### 2.1 Directory Responsibilities

| Directory | Content | Target Audience |
|-----------|---------|-----------------|
| `architecture/` | Architecture decisions, technical design, competitive analysis | Developer, architect |
| `decisions/` | ADR — context and rationale of architecture decisions | Developer, architect |
| `standards/` | Coding, testing, documentation, CI/CD standards | Developer, contributor |
| `user-manuals/en/` | Current CLI, configuration, detector, verifier, output, and integration behavior | End user; authoritative |
| `user-manuals/tr/` | Turkish translation of the English manual with identical navigation/page coverage | End user; translated |
| `guides/` | Supplemental deep dives, operational rationale, and implementation detail; must defer current product contracts to the user manual | Advanced user, operator, contributor |
| Root `docs/` | Roadmap, general documents | Everyone |

### 2.2 Canonical and Generated Boundaries

The documentation publication chain is intentionally one-way:

```mermaid
flowchart LR
    EN["docs/user-manuals/en\nAuthoritative behavior"] --> TR["docs/user-manuals/tr\nReviewed translation"]
    META["docs/user-manuals/_meta.yaml\nNavigation contract"] --> BUILD["tools/site-build"]
    EN --> BUILD
    TR --> BUILD
    BUILD --> SITE["site/js/manuals/*.js\nGenerated; do not edit"]
```

- Product behavior changes start in code and executable contracts, then update the English user manual.
- The matching Turkish page is updated in the same change. `_meta.yaml` requires identical page coverage for every declared language.
- `tools/site-build` compiles both languages into `site/js/manuals/*.js`. Generated bundles must never be edited by hand and CI rejects generated drift.
- Supplemental guides may explain advanced workflows or rationale, but they must link to the user manual for current flags, defaults, statuses, counts, and support claims. If the two disagree, the user manual and executable contract win.
- Architecture documents describe implementation. They do not redefine user-facing CLI or configuration contracts.

### 2.3 Release-Version Examples

- An example advertised as current must use `internal/meta.ReleaseVersion` (or a floating supported pin such as `@v1` or `:latest`).
- An intentionally historical example must be associated with `<!-- leakwatch-version: historical vX.Y.Z -->` in the same paragraph, table block, or fenced example and explain why that exact older value matters.
- CI scans Leakwatch-specific full-version pins across current Markdown surfaces, including root policies, contributor material, architecture, ADRs, guides, user manuals, site documentation, editor documentation, and workflow documentation. Inherently historical inventories such as the changelog and roadmap are excluded. An unmarked stale pin fails the documentation contract test.

---

## 3. Document Template

Every document should begin with the following header block:

```markdown
# Leakwatch - <Document Title>

> **Document Version:** X.Y
> **Date:** YYYY-MM-DD
> **Status:** Draft | In Review | Approved | Archived

---
```

### 3.1 Document Statuses

| Status | Description |
|--------|-------------|
| **Draft** | In initial writing phase, open to changes |
| **In Review** | Under review, awaiting feedback |
| **Approved** | Approved, can be used as a reference |
| **Archived** | Outdated, kept as historical reference |

### 3.2 ADR (Architecture Decision Record) Template

Architecture decisions are documented under `docs/decisions/` in the following format:

```markdown
# ADR-NNNN: <Decision Title>

- **Status:** Proposed | Accepted | Superseded | Rejected | Deprecated
- **Date:** YYYY-MM-DD
- **Decision Makers:** <Names or team>

## Context
The situation, problem, or need that led to the decision.

## Decision
The decision made and its rationale.

## Evaluated Alternatives
Options considered and reasons for rejection.

## Consequences
Positive and negative impacts of the decision.

## Related Decisions
Related ADRs (if any).
```

**ADR Rules:**

- File name: `ADR-NNNN-short-title.md` (lowercase, hyphen-separated)
- Sequence number is 4 digits, zero-padded: `0001`, `0002`, ...
- Each ADR is added to the `docs/decisions/README.md` index
- Accepted ADR decisions are not rewritten — record a partial change in a new ADR and mark the old ADR "Amended"; replace an entire decision only with a new ADR that marks the old one "Superseded"
- ADRs are also added to the `CLAUDE.md` reference table

---

## 4. Diagram and Visualization Standards

### 4.1 Mermaid Usage (Mandatory)

All diagrams must be drawn using **Mermaid** syntax. ASCII art or external image files must not be used.

**Rationale:**
- GitHub, GitLab, VS Code, and many Markdown viewers render Mermaid natively
- Compatible with version control (text-based, diffable)
- Consistent appearance
- Easy to maintain

### 4.2 Supported Diagram Types

| Type | Use Case | Mermaid Syntax |
|------|----------|----------------|
| **Flowchart** | Pipeline, data flow, decision tree | `flowchart TD` or `flowchart LR` |
| **Sequence Diagram** | Component interactions, API calls | `sequenceDiagram` |
| **Class Diagram** | Interfaces, type relationships | `classDiagram` |
| **State Diagram** | Lifecycles, state transitions | `stateDiagram-v2` |
| **Gantt Chart** | Timelines, roadmap | `gantt` |
| **Pie/Bar Chart** | Statistics, comparisons | `pie` / `xychart-beta` |
| **Block Diagram** | Architecture block diagrams | `block-beta` |
| **Git Graph** | Branching strategy | `gitgraph` |
| **Quadrant Chart** | Positioning matrices | `quadrantChart` |

### 4.3 Mermaid Style Rules

1. **Direction:** Top-down (`TD`) by default. Use `LR` when horizontal flow is needed.
2. **Color:** Use Mermaid's default theme; custom colors only when semantic distinction is needed.
3. **Labels:** Short and descriptive. Use text outside the diagram for longer explanations.
4. **Complexity:** A single diagram should not exceed 15-20 nodes. More complex structures should be split into sub-diagrams.
5. **Subgraphs:** Use to group related components.

### 4.4 Mermaid Examples

**Flowchart:**

````markdown
```mermaid
flowchart LR
    A[Source] --> B[Chunker]
    B --> C[Detection Engine]
    C --> D{Verification?}
    D -->|Yes| E[Verifier]
    D -->|No| F[Output]
    E --> F
```
````

**Sequence diagram:**

````markdown
```mermaid
sequenceDiagram
    participant CLI
    participant Engine
    participant Detector
    participant Verifier

    CLI->>Engine: Scan(config)
    Engine->>Detector: Scan(chunk)
    Detector-->>Engine: RawFinding[]
    Engine->>Verifier: Verify(finding)
    Verifier-->>Engine: VerificationResult
    Engine-->>CLI: Finding[]
```
````

**Class diagram:**

````markdown
```mermaid
classDiagram
    class Detector {
        <<interface>>
        +ID() string
        +Description() string
        +Keywords() []string
        +Scan(ctx, data) []RawFinding
        +Severity() Severity
    }
```
````

---

## 5. Code Example Standards

### 5.1 Code Blocks

- Every code block must specify the language: ` ```go `, ` ```yaml `, ` ```bash `
- Code examples should be compilable and runnable (whenever possible)
- Long code blocks (>50 lines) should be split into sections with explanations in between

### 5.2 Command Line Examples

```markdown
# CORRECT: Each command has an explanation before it
# Scan filesystem
leakwatch scan fs /path/to/project

# INCORRECT: Command sequence without explanations
leakwatch scan fs /path
leakwatch scan git /path
leakwatch verify aws
```

---

## 6. Table Standards

- Tables are written using GFM table syntax
- Column headers may be **bold** (`| **Header** |`) or use GFM default bold
- Tables should not exceed 5-6 columns; for wider data use multiple tables
- Prefer short phrases and links over long text in cells

---

## 7. Link Standards

### 7.1 Internal Links

- Internal document links use **relative paths**:
  ```markdown
  For details, see the [Architecture Design](../architecture/03-ARCHITECTURE.md) document.
  ```
- Same-document links use anchors:
  ```markdown
  See [Diagram Standards](#4-diagram-and-visualization-standards)
  ```

### 7.2 External Links

- External links use full URLs
- Link text should be descriptive:
  ```markdown
  # CORRECT
  [Go Effective Go guide](https://go.dev/doc/effective_go)

  # INCORRECT
  [click here](https://go.dev/doc/effective_go)
  ```

---

## 8. Change Management

1. Document updates are made via PR
2. Document version is incremented semantically (X.Y)
   - **X** — Structural or major content change
   - **Y** — Minor corrections, additions
3. Each update uses the `docs(<scope>):` prefix in the commit message
4. Outdated documents are moved to "Archived" status, not deleted

---

## 9. Review Checklist

The following checklist must be completed before opening a document PR:

- [ ] Header block (version, date, status) is present
- [ ] All diagrams are in Mermaid format
- [ ] Code blocks include a language tag
- [ ] Internal links use relative paths
- [ ] Tables do not exceed 6 columns
- [ ] Spelling has been checked
- [ ] Mermaid diagrams render correctly on GitHub (preview)
- [ ] English behavior changes have matching Turkish updates
- [ ] Generated site bundles were rebuilt and have no unexplained diff
- [ ] Leakwatch-specific release pins are current or explicitly historical
- [ ] Relative Markdown links resolve to tracked files

# Leakwatch - Phased Development Roadmap

> **Document Version:** 7.2
> **Date:** 2026-04-09
> **Status:** Approved
> **Last Updated:** 2026-08-11

---

## Current Status

| Phase | Status | Version | Date |
|-------|--------|---------|------|
| Phase 1 — MVP | Completed | `v0.1.0` | 2026-03-24 |
| Phase 2 — Git Integration | Completed | `v0.2.0` | 2026-03-24 |
| Phase 3 — Detection & Verification | Completed | `v0.3.0` | 2026-03-24 |
| Phase 4 — Enterprise Capabilities | Completed | `v0.4.0` | 2026-03-24 |
| Phase 5 — Platform Expansion | Completed (8/8) | `v1.0.0` | 2026-03-24 |
| Phase 6 — Remediation Guidance | Completed | `v1.1.0` | 2026-03-24 |
| Phase 7 — Slack Scanning | Completed | `v1.2.0` | 2026-03-24 |
| Phase 8 — Verifier Expansion | Completed | `v1.3.0` | 2026-03-25 |
| Phase 8.1 — Binary/Homebrew Fix | Completed | `v1.3.1` | 2026-03-25 |
| Phase 8.2 — CLI UX Improvements | Completed | `v1.3.2` | 2026-03-25 |
| Phase 8.3 — Scan Summary + Security | Completed | `v1.4.0` | 2026-04-08 |
| Phase 8.4 — False Positive Reduction | Completed | `v1.5.0` | 2026-04-09 |
| Phase 8.5 — GitHub Marketplace Action & Distribution | Completed | `v1.6.0` | 2026-05-25 |
| Review Remediation Release | Released | `v1.7.0` | 2026-07-19 |
| Phase 9 — Detection Accuracy & FP Reduction | Planned | `v1.8.0` | — |
| Phase 10 — Detector Library Expansion | Planned | `v1.9.0` | — |
| Phase 11 — Verification Depth & Credential Impact | Planned | `v1.10.0` | — |
| Phase 12 — Source Expansion (Confluence/Jira, org-scale) | Planned | `v1.11.0` | — |
| Phase 13 — Secrets Inventory | Planned | `v1.12.0` | — |
| Phase 14 — Honeytokens | Planned | `v1.13.0` | — |

> **Prioritization note (v7.0):** the planned sequence is re-ordered so the work that most strengthens the core promise — accurate, verified, low-noise findings — comes first. Detection accuracy and false-positive reduction (Phase 9), broader coverage of high-blast-radius credential types (Phase 10), and deeper verification with credential-impact insight (Phase 11) precede new scan sources (Phase 12) and the inventory/honeytoken platform features (Phases 13–14). Rationale is detailed in [Planned Work — Prioritization](#planned-work--prioritization).

### v1.7.0 Highlights

- **Full-project remediation release** — findings from a multi-dimensional review of the code, tests, documentation, CI/CD, VS Code extension, and website were remediated and recorded in the changelog
- **Detection and scan correctness** — expanded token coverage, per-file scanning, consistent exclusion flags, deterministic and bounded engine behavior, correct Git-history attribution, and stricter false-positive handling
- **Verification accuracy** — corrected provider endpoint/context handling and removed verification paths that could not truthfully prove credential liveness
- **Secret-safe output and transport** — raw credentials are excluded from default output and logs; panic, URL, terminal, CSV, container, and editor trust boundaries were hardened
- **Quality and supply-chain gates** — detector coverage, website drift, VS Code, Windows build, SBOM/signing, security scanning, and dependency/toolchain checks were strengthened

### v1.6.0 Highlights

- **GitHub Marketplace Action** — `uses: HodeTech/Leakwatch@v1`. Composite action that installs a prebuilt, checksum-verified binary (no Go toolchain), runs a scan, maps exit codes, writes a job summary, supports PR-diff scanning (`scan-diff`), and can upload SARIF to Code Scanning. Linux & macOS runners.
- **New `github` output format** — `--format github` emits workflow commands so findings appear as inline annotations on pull requests
- **Config keys now take effect** — `custom-rules`, `verification.*`, `filter.exclude-detectors`, and `output.severity-threshold` from `.leakwatch.yaml` are wired into the scan (previously documented but no-ops); `scan repos` honors all scan config too
- **Accurate locations & inline ignore** — findings report real line numbers; `# leakwatch:ignore[:<detector-id>]` markers are honored; SARIF results carry location-stable `partialFingerprints`
- **Distribution** — multi-arch GHCR image (public), Homebrew tap (`HodeTech/tap/leakwatch`), and cross-platform release archives with checksums
- **Security hardening** — credentials redacted in Git URLs and verifier transport errors; the composite action isolates inputs via env (no shell injection) and honors the leakwatch exit code

### v1.5.0 Highlights

- **False positive reduction** — improved filtering for lock files (`package-lock.json`, `yarn.lock`, etc.), test fixtures, and placeholder patterns
- **ADO.NET connection string support** — `dbconn` detector updated to recognize Microsoft SQL Server ADO.NET connection strings
- **Go 1.25.8 pin** — CI pinned to Go 1.25.8 (latest version available in GitHub Actions runners at the time of release)
- **PagerDuty context-aware detection** — context-based checks to reduce false positives

### v1.4.0 Highlights

- **Scan summary** — every scan prints a summary to stderr (source, target, duration, file count, findings count, verification stats)
- **`leakwatch init` command** — generates `.leakwatch.yaml` with sensible defaults
- **Colored table output** — ANSI colors by severity in the terminal table formatter (critical=red, high=yellow, medium=cyan, low=white)
- **Rich help messages** — all commands include `Example` sections
- **`.leakwatchignore` CWD fallback** — when no `.leakwatchignore` is found alongside the config file, the current working directory is also checked
- **Go 1.25.8** + go-git v5.17.1 — security patches

### v1.3.2 Highlights

- **CLI UX improvements** — more readable help messages, refined defaults
- **GoReleaser binary name fix** — forced lowercase binary name in release artifacts

### v1.3.1 Highlights

- **Homebrew automation** — CI configured with `HOMEBREW_TAP_TOKEN` for automatic Homebrew tap updates via GoReleaser
- **Community infrastructure** — Code of Conduct, issue templates, GitHub Discussions enabled

### v1.3.0 Highlights

- **54 verifiers implemented (51 packages)** — verification coverage increased from ~5% to ~85.7% (54/63)
- **Live API verification** for the majority of detectors across cloud, AI/ML, DevTools, CI/CD, communication, payment, monitoring, security, and SaaS categories
- **Format validation** for 5 detectors (Azure Storage, Azure Entra, GCP Service Account, Snowflake, RabbitMQ)
- **Per-provider rate limiting** for all verifiers with configurable limits
- **5 implementation sprints** completed: V-1 through V-5

### v1.0.0 Highlights

- **6 scan sources:** Filesystem, Git history, Container image, AWS S3, Google Cloud Storage, Slack
- **63 detectors (60 packages):** AWS, GitHub, Slack, Stripe, JWT, and many more across cloud, AI/ML, DevTools, CI/CD, communication, payment, database, infrastructure, identity, monitoring, security, and SaaS categories + YAML custom rules
- **4 output formats:** JSON, SARIF, CSV, Table
- **Aho-Corasick hybrid detection engine** with Shannon entropy analysis
- **Verifier infrastructure:** 54 verifiers (51 packages), including AWS STS and GitHub API verifiers (rate-limited, concurrent)
- **`.leakwatchignore`** and inline ignore (`# leakwatch:ignore`)
- **CI/CD:** Pre-commit hook, GitHub Action, Docker image, Homebrew formula
- **Parallel repo scanning** (`scan repos --parallel`)
- **Filtering:** `--min-severity`, `--only-verified`, `--no-verify`
- **Documentation:** 11 guides, 8 ADRs, 4 standards documents, architecture design
- **2 full code reviews** completed (136 findings identified and resolved)

---

## Roadmap Overview

Leakwatch development proceeds in incremental phases, each building on the previous one and each producing a usable deliverable. Phases 1–8 (through `v1.6.0`) and the `v1.7.0` review-remediation release are complete. Phases 9–14 remain the planned forward path beginning with `v1.8.0`, sequenced by leverage on the product's core promise — see [Planned Work — Prioritization](#planned-work--prioritization).

```mermaid
gantt
    title Leakwatch Development Roadmap
    dateFormat YYYY-MM-DD
    axisFormat %b %Y

    section Phase 1 — MVP
        Project skeleton & CLI          :done, f1a, 2026-04-01, 2w
        Detector/Source interfaces      :done, f1b, after f1a, 1w
        Filesystem scanning             :done, f1c, after f1b, 1w
        Worker pool & JSON output       :done, f1d, after f1c, 2w

    section Phase 2 — Git
        go-git integration              :done, f2a, after f1d, 2w
        scan git command                :done, f2b, after f2a, 1w
        Scan limiting (since/depth)     :done, f2c, after f2b, 1w

    section Phase 3 — Detection & Verification
        Aho-Corasick engine             :done, f3a, after f2c, 2w
        Entropy analysis                :done, f3b, after f3a, 1w
        Verifier infrastructure         :done, f3c, after f3b, 2w
        AWS/GitHub verifiers            :done, f3d, after f3c, 2w

    section Phase 4 — Enterprise
        Container image scanning        :done, f4a, after f3d, 2w
        SARIF/CSV output formats        :done, f4b, after f4a, 1w
        Pre-commit & .leakwatchignore   :done, f4c, after f4b, 2w

    section Phase 5 — Expansion
        S3/GCS scanning                 :done, f5a, after f4c, 3w
        GitHub Action & Docker          :done, f5b, after f5a, 2w
        v1.0.0 Release                  :milestone, after f5b, 0d

    section Completed v1.1-v1.6
        Remediation, Slack, Verifiers   :done, f6, after f5b, 6w
        UX, Security, FP reduction      :done, f8, after f6, 6w
        Marketplace Action & distrib.   :done, f85, after f8, 3w

    section Completed v1.7.0
        Full-project review remediation :done, f87, after f85, 4w

    section Planned v1.8.0+
        Detection accuracy & FP         :p9, after f87, 5w
        Detector library expansion      :p10, after p9, 6w
        Verification depth & impact     :p11, after p10, 6w
        Source expansion                :p12, after p11, 6w
        Secrets inventory               :p13, after p12, 5w
        Honeytokens                     :p14, after p13, 4w
```

---

## Phase 1: Minimum Viable Product (MVP) — COMPLETED

**Goal:** Build the core scan engine and CLI structure. A functional first version that can scan the local filesystem.

**Duration:** 4-6 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Project skeleton | Critical | Project structure with `cobra-cli`, `go.mod` initialization |
| CLI infrastructure | Critical | `scan fs <path>` command, `--format`, `--output`, `--concurrency` flags |
| Configuration system | Critical | Viper integration, `.leakwatch.yaml` file reading, env var support |
| Detector interface and registry | Critical | `Detector` interface, `Register()`, `All()` mechanism |
| Source interface | Critical | `Source` interface, `Chunk` and `SourceMetadata` types |
| Filesystem source | Critical | `io/fs` based `FilesystemSource` implementation |
| Worker pool | Critical | Goroutine pool, jobs/results channels, context cancellation |
| Basic detectors | High | AWS Access Key ID, RSA/SSH Private Key, Generic API Key |
| JSON output formatter | High | `Formatter` interface, JSON implementation |
| Basic filtering | Medium | File size limit, extension filtering |
| Unit tests | High | >80% test coverage for all components |
| CI pipeline | High | GitHub Actions: test, lint, build |

### Acceptance Criteria

- [x] `leakwatch scan fs /path/to/dir` command works
- [x] AWS Access Key ID, RSA Private Key are detected
- [x] Output is produced in JSON format
- [x] Worker count is configurable with `--concurrency` flag
- [x] Output can be written to file with `--output` flag
- [x] CI pipeline is green (test + lint + build)
- [x] Test coverage >80%

### Exit Criteria

GitHub Release published with `v0.1.0` tag.

---

## Phase 2: Git Integration and History Scanning — COMPLETED

**Goal:** Add the ability to scan Git repositories and their full commit histories.

**Duration:** 3-4 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| go-git integration | Critical | Add dependency, open local/remote repos |
| `scan git` command | Critical | `scan git <url_or_path>` command |
| Git source (GitSource) | Critical | Navigate commit history, read files from each commit |
| Commit metadata | High | Add commit hash, author, date, branch info to findings |
| Scan limiting | High | `--since`, `--depth`, `--branch` flags |
| Remote repo cloning | High | HTTP(S) and SSH authentication support |
| Diff-based scanning | Medium | Scan only changed files (CI/CD optimization) |
| Performance tests | Medium | Large repo benchmarks |

### Acceptance Criteria

- [x] `leakwatch scan git /path/to/repo` command works
- [x] `leakwatch scan git https://github.com/...` scans remote repo
- [x] Full commit history is scanned
- [x] Date filtering works with `--since 2024-01-01`
- [x] Commit info appears in findings
- [x] 10K-commit repo is scanned in <30 seconds

### Exit Criteria

GitHub Release published with `v0.2.0` tag.

---

## Phase 3: Advanced Detection and Verification — COMPLETED

**Goal:** Improve detection accuracy, reduce false positive rate, add secret verification.

**Duration:** 5-7 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Aho-Corasick engine | Critical | Keyword pre-filtering with pattern matching |
| Detector expansion | Critical | New detectors (Slack, Stripe, JWT, DB Connection String, etc.) |
| Shannon entropy module | High | Calculation, thresholds, regex integration |
| Verifier interface | Critical | Verification infrastructure, rate limiting, timeout |
| AWS verifier | Critical | Verification via STS GetCallerIdentity |
| GitHub verifier | High | Verification via GitHub API /user endpoint |
| Verification status output | High | VERIFIED_ACTIVE, UNVERIFIED, INACTIVE display |
| `--only-verified` flag | High | Show only verified findings |
| `--no-verify` flag | High | Disable verification |
| YAML custom rule support | Medium | User-defined regex rules (.leakwatch.yaml) |

### Acceptance Criteria

- [x] 100+ patterns matched in <1ms with Aho-Corasick
- [x] AWS key is verified (verified active/inactive)
- [x] GitHub token is verified
- [x] False positives are filtered with `--only-verified`
- [x] Low-entropy matches are flagged with entropy analysis
- [x] Custom rules can be defined via YAML

### Exit Criteria

GitHub Release published with `v0.3.0` tag. **The key differentiating feature is completed in this phase.**

---

## Phase 4: Enterprise Capabilities — COMPLETED

**Goal:** Container image scanning, advanced output formats, pre-commit integration.

**Duration:** 4-6 Weeks | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Container image source | Critical | Layer-based scanning with go-containerregistry |
| `scan image` command | Critical | `scan image <image:tag>` command |
| Registry authentication | High | Docker Hub, GHCR, ECR, GCR support |
| SARIF output format | High | GitHub Code Scanning integration |
| CSV output format | Medium | Tabular output |
| Table (human-readable) output | Medium | Terminal table for quick review |
| `.leakwatchignore` | High | .gitignore-style exclusions |
| Inline ignore | Medium | `# leakwatch:ignore` comment support |
| Pre-commit hook | High | `.pre-commit-hooks.yaml` file |
| Severity filtering | Medium | `--min-severity high` flag |

### Acceptance Criteria

- [x] `leakwatch scan image nginx:latest` command works
- [x] Deleted secrets in container layers are detected
- [x] SARIF output is accepted by GitHub Code Scanning
- [x] Pre-commit hook works
- [x] Files can be excluded with `.leakwatchignore`

### Exit Criteria

GitHub Release published with `v0.4.0` tag.

---

## Phase 5: Platform Expansion — COMPLETED

**Goal:** New scan sources, distribution channels, verifier implementations, IDE integration.

**Duration:** Continuous | **Status:** Completed

### Deliverables

| Task | Status | Description |
|------|--------|-------------|
| S3 bucket scanning | [x] Completed | `scan s3 <bucket>` with prefix filtering, region support |
| GCS bucket scanning | [x] Completed | `scan gcs <bucket>` with ADC auth, prefix filtering |
| Homebrew formula | [x] Completed | Generated by GoReleaser and pushed to the `HodeTech/homebrew-tap` repo (`brew install HodeTech/tap/leakwatch`); no `Formula/` directory is committed to this repo |
| Docker image | [x] Completed | Multi-stage Dockerfile, non-root alpine |
| GitHub Action | [x] Completed | Root `action.yml` (composite, prebuilt-binary install), Marketplace-ready, SARIF upload, PR-diff (`--since-commit`), inline annotations |
| AWS & GitHub verifiers | [x] Completed | AWS STS GetCallerIdentity, GitHub /user API |
| Parallel repo scanning | [x] Completed | `scan repos` with `--parallel` flag |
| VS Code extension | [x] Completed | Diagnostics, scan-on-save, status bar, workspace/file scan |

### Acceptance Criteria

- [x] `leakwatch scan s3 my-bucket` scans S3 objects
- [x] `leakwatch scan gcs my-bucket` scans GCS objects
- [x] `leakwatch scan repos url1 url2 --parallel 5` scans multiple repos
- [x] Docker image runs scans without local installation
- [x] GitHub Action uploads SARIF to Code Scanning
- [x] AWS keys are verified via STS
- [x] VS Code extension provides inline diagnostics and scan-on-save

### Exit Criteria

GitHub Release published with `v1.0.0` tag.

---

## Phase 6: Remediation Guidance — COMPLETED

**Goal:** Actionable remediation instructions for every detected secret type.

**Duration:** 2 weeks | **Version:** `v1.1.0` | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Remediation type | Critical | `Remediation` struct in `pkg/finding/finding.go` |
| Remediation registry | Critical | Per-detector remediation data with rotation steps, doc URLs |
| Formatter updates | High | JSON, SARIF, CSV, Table all display remediation |
| CLI flags | High | `--remediation`, `--remediation-format brief\|full` |
| Tests | High | Registry and enrichment tests |

### Acceptance Criteria

- [x] `leakwatch scan fs /path --remediation` includes rotation steps
- [x] SARIF output includes remediation in rule `help` property
- [x] All 10+ detectors have remediation guidance

---

## Phase 7: Slack Workspace Scanning — COMPLETED

**Goal:** Scan Slack messages, channels, and files for leaked secrets.

**Duration:** 3-4 weeks | **Version:** `v1.2.0` | **Status:** Completed

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| SlackSource | Critical | `source.Source` implementation with rate-limited pagination |
| Slack client interface | Critical | Testable `slackClient` abstraction |
| `scan slack` command | Critical | Channel/date filtering, DM opt-in |
| SourceMetadata fields | High | Channel, user, timestamp in findings |
| Tests | High | Mocked client tests |
| Guide | Medium | `docs/guides/slack-scanning.md` |

### Acceptance Criteria

- [x] `leakwatch scan slack --token xoxb-...` scans workspace
- [x] Channel filtering works with `--channels`
- [x] Date filtering works with `--since`
- [x] Rate limiting respects Slack API tiers

---

## Phase 8: Verifier Expansion — COMPLETED

**Goal:** Increase verification coverage to ~85.7% (54/63). Verified secrets are the key differentiator.

**Duration:** 5 sprints | **Version:** `v1.3.0` | **Status:** Completed

**Analysis:** [docs/architecture/05-VERIFIER-ANALYSIS.md](architecture/05-VERIFIER-ANALYSIS.md)

### Deliverables

| Sprint | Verifiers | Coverage | Status |
|--------|-----------|----------|--------|
| V-1 (Tier 1 P0) | OpenAI, Anthropic, GitLab, SendGrid, DigitalOcean, Cloudflare, Heroku, New Relic, Telegram, Discord, Notion | 14/63 (22%) | [x] Completed |
| V-2 (Tier 1 P1) | Sentry, Vercel, NPM, PyPI, Grafana, PagerDuty, Databricks, Linear, Figma, Airtable, HuggingFace, CircleCI | 26/63 (41%) | [x] Completed |
| V-3 (Tier 1 P2) | DockerHub, Doppler, Snyk, SonarCloud, Postmark, Terraform, LaunchDarkly, Mailgun, Coinbase, Infura | 36/63 (57%) | [x] Completed |
| V-4 (Tier 2) | Okta, Shopify, Stripe, Twilio, Bitbucket, Auth0, Datadog, RubyGems, DeepSeek, Supabase | 47/63 (75%) | [x] Completed |
| V-5 (Tier 2+3) | GitHub OAuth, Teams Webhook, Azure Storage, Azure Entra, GCP, Snowflake, RabbitMQ | 54/63 (85.7%) | [x] Completed |

**Final totals:** 54 verifiers (51 packages) covering 63 detectors (60 packages).

### Acceptance Criteria

- [x] Verification coverage reaches ~85.7% (54/63)
- [x] All Tier 1 verifiers use simple HTTP GET/POST pattern
- [x] Rate limiting per provider (configurable)
- [x] `--only-verified` returns results for the verified detector types
- [x] Never log raw credentials during verification

---

## Planned Work — Prioritization

The product's core promise is **accurate, verified, low-noise secret findings**. Planned phases are sequenced by how directly they serve that promise, balanced against effort:

1. **Sharpen what we already detect first (Phase 9).** Tightening detector precision/recall and cutting false positives is the highest-leverage, lowest-effort work: it raises the quality of *every* scan immediately and protects user trust. It also closes the remaining "documented but not yet behaving as promised" gaps (see the [traceability index](#documented-gap-traceability)).
2. **Broaden coverage of high-impact credentials (Phase 10).** Once accuracy is solid, grow the detector library toward the credential types with the largest blast radius.
3. **Make verification deeper and more useful (Phase 11).** Verification is the differentiator; harden the engine, verify more credential classes, and tell users what a live secret can actually reach.
4. **Reach secrets in more places (Phase 12).** New scan sources (collaboration platforms, org-scale code hosting) extend reach after the core is strong.
5. **Platform features last (Phases 13–14).** Persistent inventory and decoy credentials build on a trustworthy, broad, well-verified core.

**Prioritization lens** — each task is weighed on: *(a)* impact on finding quality (precision/recall/verification), *(b)* blast radius of the credentials it touches, *(c)* effort, and *(d)* whether it makes an already-promised capability behave correctly. Within each phase, tables list per-task priority (Critical / High / Medium / Low).

---

## Phase 9: Detection Accuracy & False-Positive Reduction — PLANNED

**Goal:** Make accuracy a measurable strength. Raise detector precision and recall, cut false positives across the board, and ensure every documented detection/verification behavior actually fires. This phase improves the quality of every existing scan without adding new surfaces.

**Duration:** 4-5 weeks | **Version:** `v1.8.0` | **Status:** Planned

### Deliverables

| Task | Status | Priority | Description |
|------|--------|----------|-------------|
| Centralized false-positive filter | Planned | Critical | Shared module applied before verification: common placeholder values, a dictionary/word-list of dummy strings, and known non-secret patterns, so individual detectors no longer each re-implement ad-hoc skips |
| Engine-level entropy gating | Delivered in `v1.7.0` | Critical | The configured `detection.entropy.threshold` gates heuristic findings engine-wide while structural detectors remain eligible |
| Keyword pre-filters for high-noise detectors | Planned | High | Add Aho-Corasick pre-filter keywords / context anchors to detectors that still scan every chunk; validate them against the accuracy corpus |
| Broaden OpenAI key coverage | Delivered in `v1.7.0` | High | Legacy and service-account variants ship alongside project keys, anchored on provider-specific structure |
| GitHub fine-grained PAT support | Delivered in `v1.7.0` | High | Fine-grained personal access tokens (`github_pat_`) are detected |
| Trusted Shopify issuer configuration | Delivered after `v1.7.0` | High | The CLI accepts only an explicit, validated operator-controlled store origin; finding-controlled domains never select the target |
| Tighten Anthropic key regex | Planned | Medium | Anchor exact length and trailing marker; distinguish admin from standard keys |
| Mailgun & JWT format breadth | Planned | Medium | Add the alternate Mailgun key format; broaden JWT matching to pretty-printed / base64-variant headers and optional padding |
| Supabase service-role detection | Planned | Medium | Detect service-role JWTs (`role: service_role`) in addition to management PATs; the existing `sbp_` detector is explicitly documented as a Management PAT |
| Bounded result buffering | Delivered in `v1.7.0` | Medium | Scan result memory is explicitly bounded before verification |
| Accuracy benchmark suite | Planned | High | Curated true/false corpus measuring precision and recall per detector, run in CI to guard against regressions |

### Acceptance Criteria

- [ ] Verified-mode false-positive rate is measured on the benchmark corpus and meets the `<5%` target
- [x] The configured entropy threshold gates findings engine-wide, not only for custom rules (`v1.7.0`)
- [ ] Telegram/Discord (and other previously keyword-less detectors) no longer fire on unrelated numeric/base64 strings in the corpus
- [x] Shopify findings reach verification only through a validated operator-trusted store origin; Okta and Bitbucket retain their detector-to-verifier context wiring (post-`v1.7.0`, awaiting the next release)
- [x] OpenAI legacy/service-account keys and GitHub `github_pat_` tokens are detected (`v1.7.0`)
- [ ] Detector test coverage stays ≥95% for every touched detector

### Exit Criteria

GitHub Release published with `v1.8.0` tag.

---

## Phase 10: Detector Library Expansion — PLANNED

**Goal:** Grow coverage of frequently-leaked, high-blast-radius credential types, prioritizing secrets whose exposure causes the most damage. Every new detector with a public verification endpoint ships with its verifier.

**Duration:** 5-6 weeks | **Version:** `v1.9.0` | **Status:** Planned

### Deliverables

| Category | Priority | Target credential types |
|----------|----------|-------------------------|
| Elevated AI / model-platform keys | High | Admin-tier model-platform keys and additional widely-used model/inference providers (e.g. Gemini, Groq) |
| Cloud identity & platform | High | Cloud application-default credentials; expanded coverage of a major cloud's service family — managed database, search, DevOps tokens, SAS tokens, function keys, container registry, app-config connection strings |
| VCS & CI/CD | High | OAuth-type VCS tokens, application/installation private keys, and additional CI/CD provider tokens |
| Correlated multi-field detection | High | A general mechanism to detect credentials that span multiple fields (identifier + secret) and pair them — improving both precision (require the pair) and verifiability (need both parts) |
| Communication & delivery | Medium | Incoming-webhook URLs and additional email/SMS delivery providers |
| Observability | Medium | Application/event keys for monitoring and error-tracking platforms |
| Security & OSINT tooling | Medium | API keys for common security/recon services |

### Acceptance Criteria

- [ ] Detector count grows toward the 12-month coverage target, with ≥95% per-detector test coverage maintained
- [ ] Each new detector that has a public verification endpoint ships with a matching verifier
- [ ] Correlated multi-field detection pairs an identifier with its secret and feeds both to verification
- [ ] No regression in the Phase 9 accuracy benchmark

### Exit Criteria

GitHub Release published with `v1.9.0` tag.

---

## Phase 11: Verification Depth & Credential Impact — PLANNED

**Goal:** Deepen the verification differentiator. Harden the verification engine, verify more credential classes, and — for live secrets — tell users what the credential can actually reach so they can triage blast radius.

**Duration:** 5-6 weeks | **Version:** `v1.10.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Per-provider rate limiting, caching & backoff | Critical | Replace the single global token-bucket limiter with per-provider limits, response caching to avoid re-verifying identical secrets, and exponential backoff/retry on transient failures |
| Canary-safe verification | High | Recognize well-known decoy/canary credential formats and skip live verification for them, so a scan never triggers an alert on someone else's planted token |
| Active private-key verification | High | Where a safe check exists, derive the public key from a detected private key and confirm liveness/association; introduce a distinct "verified key material" status that does not overstate access |
| Credential impact analysis | High | Opt-in: for a verified secret, enumerate its effective permissions and reachable resources, starting with the highest-value providers, so users understand blast radius — not just that a secret is live |
| Verification status refinements | Medium | Distinguish network/rate-limit failures from genuine "inactive"; surface the distinction in output and in `--only-verified`/filter semantics |

### Acceptance Criteria

- [ ] Per-provider limits and response caching are verified under load; transient failures retry with backoff
- [ ] Known canary credential formats are never sent to a live endpoint
- [ ] Private-key findings can reach a "verified key material" status without implying broader access
- [ ] Impact analysis produces a permission/resource summary for at least the top-priority providers
- [ ] Network/rate-limit errors are no longer reported as "inactive"

### Exit Criteria

GitHub Release published with `v1.10.0` tag.

---

## Phase 12: Source Expansion — PLANNED

**Goal:** Reach secrets wherever they live — collaboration platforms and org-scale code hosting — now that the detection/verification core is strong.

**Duration:** 5-6 weeks | **Version:** `v1.11.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Atlassian shared client | Critical | HTTP client with Cloud + Server/DC auth |
| ConfluenceSource | Critical | Space/page pagination, HTML extraction |
| JiraSource | Critical | JQL query, issue/comment scanning |
| `scan confluence` command | Critical | Space filtering, attachment scanning |
| `scan jira` command | Critical | Project filtering, JQL support |
| Org-scale repository enumeration | High | Scan every repository (and its history) under an organization/group via the hosting API, instead of a single local/remote repo at a time |
| Slack file content scanning | Medium | Fetch and scan file attachments via the Files API, completing the `--include-files` flag that is currently accepted but a no-op |
| SourceMetadata fields | High | Space, page, issue key, org/repo context in findings |
| Additional platform sources | Low | API-collection platforms, CI systems, and search clusters as demand warrants |
| Tests | High | `httptest.NewServer` mocks |
| Guide | Medium | `docs/guides/atlassian-scanning.md`, `docs/guides/org-scanning.md` |

### Acceptance Criteria

- [ ] `leakwatch scan confluence --url URL --api-token TOKEN` scans pages
- [ ] `leakwatch scan jira --url URL --jql "project=SEC"` scans issues
- [ ] Both Cloud and Server editions supported
- [ ] HTML content properly extracted from Confluence storage format
- [ ] An entire organization's repositories can be enumerated and scanned from a single command
- [ ] Slack file attachments are fetched and scanned when `--include-files` is set

### Exit Criteria

GitHub Release published with `v1.11.0` tag.

---

## Phase 13: Secrets Inventory — PLANNED

**Goal:** Persistent SQLite-based inventory tracking secrets across scans.

**Duration:** 4-5 weeks | **Version:** `v1.12.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| SQLite store | Critical | Pure Go `modernc.org/sqlite`, WAL mode |
| Inventory service | Critical | Upsert, dedup, status tracking |
| `inventory list` | Critical | Filter by status, severity, source |
| `inventory stats` | High | Aggregate statistics |
| `inventory show/update` | High | Detail view, status changes |
| `inventory export` | Medium | JSON/CSV export |
| `inventory reverify` | Medium | Re-verify active secrets |
| Scan integration | Critical | `--inventory` flag on all scan commands |
| Tests | High | In-memory SQLite tests |
| Guide | Medium | `docs/guides/secrets-inventory.md` |

### Acceptance Criteria

- [ ] `leakwatch scan fs /path --inventory` persists findings
- [ ] `leakwatch inventory list --status active` shows tracked secrets
- [ ] `leakwatch inventory stats` shows aggregate counts
- [ ] Deduplication across multiple scan runs
- [ ] Only redacted values stored (never raw secrets)

### Exit Criteria

GitHub Release published with `v1.12.0` tag.

---

## Phase 14: Honeytokens — PLANNED

**Goal:** Generate and deploy decoy credentials that alert on unauthorized use.

**Duration:** 3-4 weeks | **Version:** `v1.13.0` | **Status:** Planned

### Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Generator framework | Critical | AWS, GitHub, generic key generators |
| Honeytoken store | Critical | SQLite persistence (shares inventory DB) |
| Webhook alerter | Critical | HTTP POST on trigger detection |
| `honeytoken generate` | Critical | Create fake credentials |
| `honeytoken deploy` | High | Inject into .env/yaml/json files |
| `honeytoken list/revoke` | High | Management commands |
| `honeytoken check` | High | Check for triggered tokens |
| Scan integration | Medium | `--detect-honeytokens` flag |
| Tests | High | Generator, store, alerter tests |
| Guide | Medium | `docs/guides/honeytokens.md` |

### Acceptance Criteria

- [ ] `leakwatch honeytoken generate --type aws` produces realistic fake key
- [ ] `leakwatch honeytoken deploy <id> .env` injects into file
- [ ] Webhook fires when honeytoken is detected in unexpected location
- [ ] Value shown once during generation, only hash persisted

### Exit Criteria

GitHub Release published with `v1.13.0` tag.

---

## Documented Gap Traceability

Earlier reviews recorded behaviors that the documentation or public interface promised but the code did not yet deliver. Rather than tracking them as a loose list, each is now **owned by a planned phase** above so it ships as part of a coherent release. This table is the index; the detail for the still-open code-quality items follows under [Engineering Hygiene Backlog](#engineering-hygiene-backlog).

| Gap | Owning phase |
|-----|--------------|
| Engine-level entropy-threshold gating | Phase 9 |
| okta / shopify / bitbucket verification never reaches verified (missing `ExtraData`) | Phase 9 |
| Supabase service-role JWT not detected (only management PAT) | Phase 9 |
| Unbounded in-memory result buffering | Phase 9 |
| `--remediation-format brief\|full` flag not implemented | Phase 9 (minor) |
| Per-provider rate limiting, verification caching, exponential backoff/retry | Phase 11 |
| Slack file scanning (`--include-files` is a no-op) | Phase 12 |

> **Minor item — `--remediation-format`:** today only a boolean `--remediation` flag exists; the `brief|full` variant referenced in the Phase 6 deliverables and the verification guide is unimplemented. Small UX task, folded into Phase 9.

---

## Engineering Hygiene Backlog

These are **not feature phases** — they are ongoing code-quality and correctness items that run in parallel with the roadmap: features the documentation promised but the code did not deliver (now resolved), code-quality findings from the PR #6 cleanup pass, and refactors flagged by SonarCloud that warrant their own focused review. Tracked here so nothing slips through the cracks.

**Source:** PR #6 (chore/docs-cleanup-and-sonar-alignment) verification pass and SonarCloud scan of `cemililik_Leakwatch` taken 2026-05-21.

### P0 — Functional Bugs (documented features that did not work) — ✅ RESOLVED

All three were fixed in branch `fix/wire-custom-rules-and-inline-ignore` (PR #7). Each was a feature referenced in the public guides whose wiring was missing from the scan pipeline; each is now wired up, tested, and verified end-to-end with the real CLI.

| # | Bug | Resolution |
|---|-----|------------|
| 1 | **YAML `custom-rules:` was never loaded** — `custom.RegisterCustomRules` existed with tests but had no caller, so user-defined detectors were silently ignored. | `Config.CustomRules []custom.RuleDef` added and bound via Viper; `executeScan` now calls `custom.RegisterCustomRules` before `detector.All()`. Registration is **duplicate-safe**: `RegisterCustomRules` pre-checks `detector.Get(id)` and skips colliding IDs with an error instead of panicking (the registry panics on duplicate IDs). Verified: a `custom-rules:` block in `.leakwatch.yaml` now produces findings; a rule colliding with `aws-access-key-id` is skipped with a warning, no panic. |
| 2 | **Inline ignore (`# leakwatch:ignore[:<id>]`) was not applied** — helpers existed but `executeScan` never invoked them; also impossible because no source set a line number. | Engine now computes line numbers (see below) and the worker drops any finding whose source line carries the marker, **before** verification. New exported helper `filter.LineHasInlineIgnore(data, lineNum, detectorID)` is shared by the worker and the existing `FilterFindingsByInlineIgnore` (DRY). Verified: a secret on a `# leakwatch:ignore` line is not reported; a `:<other-detector>` marker does not suppress unrelated detectors. |
| 3 | **`verification.*` YAML config was not bound** — `verification.enabled/timeout/concurrency/rate-limit` were emitted by `leakwatch init` and documented but had no `VerificationConfig` struct. | `VerificationConfig` added with Viper binding + validation (positive timeout/concurrency/rate-limit); `executeScan` builds the `verifier.Config` from it. `--no-verify` still takes precedence. Verified: `verification.enabled: false` leaves findings `unverified` (no network call); an invalid `timeout: 0s` is rejected at load time. |

**Prerequisite delivered as part of the fix — line-number tracking:** no source (`filesystem`, `git`, …) ever set `SourceMetadata.Line`, so every finding reported `line: 0`. `engine.rawToFinding` now derives the 1-based line from the match's byte offset within the chunk (guarded by `Line == 0` so a future line-aware source is respected). This both powers inline ignore and fixes the long-standing `line: 0` gap in JSON/SARIF/CSV/table output.

### P1 — Config Schema Drift — ✅ MOSTLY RESOLVED

Fixed in PR #7 alongside the P0 items (same "documented but no-op" category):

| YAML key | Status |
|---|---|
| `output.severity-threshold` | ✅ Bound. `--min-severity` still takes precedence (verified). |
| `filter.exclude-detectors` | ✅ Bound. Listed detector IDs are removed from the active set before scanning (verified: excluding `aws-access-key-id` yields zero AWS findings). |
| `slack.token`, `slack.channels`, `slack.exclude-channels`, `slack.include-dms`, `slack.include-files`, `slack.rate-limit` | ⏳ **Still flag-only.** The `scan slack` command is fully functional via CLI flags / `LEAKWATCH_SLACK_TOKEN`; reading these from `.leakwatch.yaml` is a nice-to-have, not a correctness gap. Deferred — bind in a future `scan slack` config pass, or trim them from `configuration.md`. |

### P1 — SonarCloud Findings Still Open

PR #6 closed: 8 BLOCKER vulns (`action.yml` script injection), 110 × `godre:S8184` blank-import smell, 13 × `go:S1192` in `remediation/guidance.go`, 2 hotspots (Dockerfile + release.yml). Remaining open findings as of the 2026-05-21 scan:

| Rule | Count | Severity | Where | Plan |
|---|---:|---|---|---|
| `go:S3776` Cognitive complexity > 15 | 11 funcs | Critical | [internal/source/git/git.go:269](../internal/source/git/git.go) (**cog 49**), `s3.go:122` (31), `git.go:164` (29), `cmd/scan_common.go:154` (29), `scan_repos.go:60` (26), `filesystem.go:67` (24), `container.go:116` (22), `sarif_formatter.go:121` (22), `slack.go:196` (19), `gcs.go:174` (16), `table_formatter.go:37` (16) | Extract-method refactor per function. `git.go:269` is the highest priority (49 ≫ 15). |
| `go:S1192` | 1 | Critical | `internal/verifier/infura/infura_verifier.go:93` — `"Infura API key is invalid or revoked"` ×3 | Local `const`. |
| `go:S108` Empty test block | 2 | Major | `gcs_test.go:321`, `s3_test.go:242` | Either remove or add `TODO` + meaningful assertion. |
| `godre:S8196` One-method interface naming | 3 | Minor | `cmd/scan_common.go:34`, `internal/source/gcs/gcs.go:45`, `internal/verifier/aws/aws_verifier.go:22` | Rename to `-er` suffix (project naming convention). |
| `godre:S8205` Nested anonymous struct | 2 | Minor | `terraform_verifier.go:107`, `linear_verifier.go:112` | Promote to named type. |
| `godre:S8209` Consecutive same-type params | 1 | Minor | `internal/filter/inline.go:27` | Group params (`a, b string` rather than `a string, b string`). |
| `typescript:S6551` | 7 | Minor | `vscode/src/scanner.ts` | Replace `?? ""` non-string fallbacks with explicit `String(...)` casts. |
| `typescript:S7772` | 2-3 | Minor | `vscode/src/extension.ts`, `scanner.ts`, `webpack.config.js` | Use `node:` prefix for `path`, `child_process`. |
| `typescript:S7778` | 2 | Minor | `vscode/src/extension.ts` | Combine consecutive `push(a); push(b);` into `push(a, b)`. |
| `docker:S7020` | 1 | Minor | `Dockerfile:11` | Likely already closed by the PR #6 line split; verify on next scan. |

### P1 — SonarCloud Project Hygiene

- **Quality Gate** — was `NONE` at the time of PR #6's first verification scan; the default "Sonar way" gate is now in effect. It Quality-Gate-Failed PR #6 twice on `new_duplicated_lines_density` (11.6%, then 11.0% after the first fix attempt). Root cause: **SonarCloud Automatic Analysis does not read `sonar-project.properties`** — that file is only honored by CI Based Analysis. Fix landed in PR #6: the exclusions in `sonar-project.properties` were also mirrored to the project via the Settings API (`POST /api/settings/set` for `sonar.cpd.exclusions`, `sonar.exclusions`, `sonar.coverage.exclusions`). **Action remaining:** verify the assigned gate is the project owner's preference; revisit the cpd exclusions in any future refactor PR (especially the verifier-httpapi extraction listed under P2).
- **`sonar-project.properties`** — added in PR #6 as a canonical source-of-truth file and as the configuration that CI Based Analysis would use. It is currently a documentation artifact (Automatic Analysis ignores it). **Done.**
- **`.github/workflows/sonar.yml`** — still missing. A dedicated workflow with `SonarSource/sonarqube-scan-action` would (a) enable per-PR coverage upload, (b) make `sonar-project.properties` the live source of truth (no more API mirroring), and (c) tighten the PR feedback loop. **Action:** add as a small chore PR once `SONAR_TOKEN` is configured as a repo secret. The Automatic Analysis must be **disabled** in the SonarCloud UI at the same time, otherwise the two analysis paths will fight each other.

### P2 — Duplication Refactor Opportunities

SonarCloud reports the project at **36.8% duplicated lines**. PR #6 dramatically reduced one source (the remediation registry — was 99.3% density). Remaining major duplication clusters:

| Refactor | Files affected | Estimated dedup |
|---|---|---|
| **`internal/verifier/httpapi` generic HTTP helper** (Bearer/Basic + JSON body + status-code → `VerificationStatus` map) | 14+ verifier packages (anthropic, openai, deepseek, github, huggingface, gitlab, dockerhub, discord, circleci, etc., each at ~95% density and ~100-130 lines) | ~6 000 → ~1 000 duplicate lines |
| **`internal/verifier/testutil/verifierharness`** table-driven HTTP mock | 14+ `_test.go` files mirror the same setup/teardown for table-driven HTTP tests (sendgrid, snyk, rubygems, npm, dockerhub, heroku, sentry, notion, ...) | ~1 500 → ~300 duplicate lines |
| **`internal/detector/credstring`** common `scheme://user:pass@host` detector | 4 connection-string detectors (FTP, Redis, RabbitMQ, LDAP — tests are ~92% byte-identical) and their tests | ~500 → ~150 duplicate lines |

Combined target: **project duplication 36.8% → ~10%**. Each of these is architectural — open a dedicated PR per refactor, not a mega-commit.

### P2 — Coverage Gaps

CLAUDE.md sets the detector-coverage standard at **≥95%**. Packages currently below or at the edge:

| Package | Coverage | Standard | Note |
|---|---:|---|---|
| `detector/generic` | 82.1% | 95% | Entropy paths not all exercised. |
| `detector/heroku` | 93.8% | 95% | One regex branch uncovered. |
| `detector/privatekey` | 92.3% | 95% | DSA / EC / PGP branches less covered than RSA / SSH. |
| `detector/snowflake` | 92.3% | 95% | Format validator edge cases. |
| `detector/stripe` | 92.3% | 95% | Live + test key duplication; testutil refactor (P2 above) helps here. |

Source packages (no formal standard, but visible gaps):

| Package | Coverage |
|---|---:|
| `source/container` | 55.2% |
| `source/git` | 64.2% |
| `source/gcs` | 71.3% |
| `source/s3` | 73.6% |

### P2 — Miscellaneous

- **VS Code extension custom rules path setting** ([vscode-extension.md](guides/vscode-extension.md) `leakwatch.customRulesPath`) is wired through to the CLI via `--custom-rules`, but the CLI side does nothing until P0 #1 is fixed. Will auto-resolve.
- **JWT format-only verifier (optional future):** `internal/verifier/jwt/` does not exist. If we ever want format-only verification for JWTs (decode + `exp` check) we need a new verification status semantic ("verified_well_formed" or similar) to avoid implying the token grants access. Until then, JWT findings are correctly classified as "Not Verifiable".

### P3 — Long-tail Notes

- **Missing `v1.1.0` / `v1.2.0` git tags:** Phase 6 and Phase 7 were released as part of `v1.3.0` without intermediate tags. Backfilling tags retroactively is optional (`git tag v1.1.0 <commit>; git tag v1.2.0 <commit>; git push --tags`) — useful for some package indexers, not blocking. See note under Release Plan.
- **Self-scan noise from test fixtures:** detector and verifier tests embed synthetic keys that match their own regex. `.leakwatchignore` already excludes `**/*_test.go` and `internal/verifier/**` for user-facing scans; running `leakwatch scan fs .` inside this repo with the default ignore will still find a handful in `rules/examples.yaml` and docs — acceptable.

---

## Future: Long Term Vision

| Task | Description |
|------|-------------|
| ML-based detection | Machine learning for unknown secret formats |
| Vault integration | Automatic rotation with HashiCorp Vault / AWS Secrets Manager |
| SaaS platform | Centralized management dashboard |
| API mode | Run Leakwatch as a service |
| Webhook notifications | Slack, Teams, PagerDuty integrations |

---

## Release Plan

| Version | Phase | Description | Date |
|---------|-------|-------------|------|
| `v0.1.0` | Phase 1 | MVP — Filesystem scanning, basic detectors | 2026-03-24 |
| `v0.2.0` | Phase 2 | Git history scanning | 2026-03-24 |
| `v0.3.0` | Phase 3 | Verification, Aho-Corasick, entropy | 2026-03-24 |
| `v0.4.0` | Phase 4 | Container scanning, SARIF, pre-commit | 2026-03-24 |
| `v1.0.0` | Phase 5 | S3/GCS, verifiers, GitHub Action, Docker | 2026-03-24 |
| `v1.1.0` | Phase 6 | Remediation guidance for all detectors (no git tag — see note) | — |
| `v1.2.0` | Phase 7 | Slack workspace scanning (no git tag — see note) | — |
| `v1.3.0` | Phase 8 | Verifier expansion (~85.7% coverage, 54/63) | 2026-03-25 |
| `v1.3.1` | Phase 8.1 | Binary/Homebrew fix, community infrastructure | 2026-03-25 |
| `v1.3.2` | Phase 8.2 | CLI UX improvements | 2026-03-25 |
| `v1.4.0` | Phase 8.3 | Scan summary, `init` command, colored table, security patches | 2026-04-08 |
| `v1.5.0` | Phase 8.4 | False positive reduction, ADO.NET support | 2026-04-09 |
| `v1.6.0` | Phase 8.5 | GitHub Marketplace Action, `github` output format, config wiring | 2026-05-25 |
| `v1.7.0` | Review Remediation | Full-project review remediation, correctness, security, and CI hardening | 2026-07-19 |
| `v1.8.0` | Phase 9 | Detection accuracy & false-positive reduction | — |
| `v1.9.0` | Phase 10 | Detector library expansion | — |
| `v1.10.0` | Phase 11 | Verification depth & credential impact | — |
| `v1.11.0` | Phase 12 | Source expansion (Confluence/Jira, org-scale) | — |
| `v1.12.0` | Phase 13 | Secrets inventory (SQLite) | — |
| `v1.13.0` | Phase 14 | Honeytokens | — |
| `v2.x.x` | Future | ML detection, SaaS platform, Vault | Ongoing |

> **Note on v1.1.0 / v1.2.0:** Phase 6 (Remediation Guidance) and Phase 7 (Slack Scanning) were completed and merged into `main`, but no `v1.1.0` or `v1.2.0` git tags were ever created. The features shipped as part of the `v1.3.0` release. The version slots are preserved here to keep the phase-to-version mapping consistent.

---

## Success Metrics

### Technical

| Metric | Target | Measurement |
|--------|--------|-------------|
| Test coverage | >70% overall, >95% detectors | `go test -cover` |
| False positive rate | <5% (verified mode) | Benchmark test suite |
| Scan speed (10K commits) | <30 seconds | CI benchmark |
| Memory usage | <512MB (medium repo) | pprof |
| Binary size | <30MB | GoReleaser |
| CI pipeline duration | <5 minutes | GitHub Actions |

### Community

| Metric | 6-Month Target | 12-Month Target |
|--------|----------------|-----------------|
| GitHub Stars | 500+ | 2,000+ |
| Contributors | 5+ | 15+ |
| Detector count | 65 (achieved) | 120+ |
| Verifier count | 54 (achieved) | 80+ |
| Source count | 6 (fs, git, container, S3, GCS, Slack) | 9+ |

---

## Risk Management

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Go regex performance is insufficient | Medium | High | Aho-Corasick pre-filtering; Rust FFI if needed |
| Slow community adoption | High | Medium | Quality documentation, example projects, blog posts |
| Existing tools evolve rapidly | Medium | Medium | Focus on differentiation (MIT + verification combo) |
| Solo developer burnout | High | High | Small phase-based goals, encourage community contributions |
| API verification rate limiting | Medium | Low | Smart rate limiting, caching, `--no-verify` option |

---

## Master Review — Documented-but-Unimplemented Gaps

> **Historical snapshot — superseded 2026-08-11:** this inventory preserves the findings as they were recorded during the 2026-05-22 review; it is not a current implementation-status dashboard. The `v1.7.0` release and subsequent review-remediation wave commits have closed or reclassified multiple rows. Current behavior is defined by the executable registry/capability contracts, their CI tests, the user manuals, and the changelog. Future audits must create a new dated snapshot rather than silently rewriting this one.
>
> The working `review/FIX-PLAN.md` remains an untracked audit artifact and is intentionally not treated as release metadata. Git commits are the authoritative closure record for the remediation waves.

> At capture time, this section was the **detailed reference** for gaps found in the 2026-05-22 full-project review. The "Owning phase" column records the scheduling decision made in that snapshot; "not implemented" statements below describe the code at that date and must not be read as current status.

| # | Gap | One-line description | Area affected | Owning phase |
|---|-----|----------------------|---------------|--------------|
| 1 | **Slack file scanning** | `--include-files` flag is accepted and documented but is a no-op; the `SlackSource` never fetches file content from the Slack Files API. | `internal/source/slack/slack.go`, `docs/guides/slack-scanning.md`, CHANGELOG v1.2.0 | Phase 12 |
| 2 | **Per-provider rate limiting, verification caching, exponential backoff/retry** | The verifier engine has a single global token-bucket rate limiter; there is no per-provider limit, no response caching, and no retry with backoff. Phase 8 deliverables and the ROADMAP claim per-provider rate limiting is implemented. | `internal/verifier/engine.go`, Phase 8 deliverables table, v1.3.0 highlights | Phase 11 |
| 3 | **`--remediation-format brief\|full` flag** | Only a boolean `--remediation` flag exists; the two-value `brief\|full` variant mentioned in Phase 6 deliverables and `docs/guides/secret-verification.md` is not implemented. | `cmd/scan_common.go`, Phase 6 deliverables table | Phase 9 (minor) |
| 4 | **Engine-level entropy-threshold gating** | The `detection.entropy.threshold` config value is read and displayed in scan summaries, but the detection engine does not gate findings on it; only custom YAML rules apply their own per-rule entropy threshold. | `internal/engine/`, `internal/config/`, `docs/guides/configuration.md` | Phase 9 |
| 5 | **Shopify trusted-store configuration** | Shopify access-token formats do not identify their issuing store. The verifier deliberately ignores finding-controlled domains and remains `StatusUnverified` until a validated, operator-controlled store origin is available. The read-only 2026-07 GraphQL verifier contract is prepared; Okta and Bitbucket companion context is already wired. | `internal/verifier/shopify/`, `internal/detector/shopify/`, and scan configuration | Phase 9 |
| 6 | **Supabase real service-role JWT detection** | The `supabase` detector matches the `sbp_` prefix which identifies Supabase Management PATs, not service-role JWTs. Service-role JWTs (`eyJ...` with `role: service_role`) are not detected; the name `supabase-service-key` implies broader coverage than is implemented. | `internal/detector/supabase/supabase_key.go`, README detector table | Phase 9 |
| 7 | **Unbounded in-memory result buffering** | The scan engine collects all raw findings into a single in-memory slice before passing them to the verification phase — there is no streaming path and no cap on the buffer size. This is acceptable for typical inputs but is a known limitation for very large or adversarial inputs (e.g., a repository engineered to maximise regex matches) where memory consumption could become excessive. Streaming verification or an explicit buffer cap is planned. | `internal/engine/engine.go` | Phase 9 |

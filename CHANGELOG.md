# Changelog

All notable changes to Leakwatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **GitHub Action is now Marketplace-ready and installs a prebuilt binary** — the action metadata moved from `action/action.yml` to the repository root `action.yml` so it can be published to the GitHub Marketplace and consumed as `uses: HodeTech/Leakwatch@v1`. Instead of compiling from source with `go install` on every run, the action now downloads the platform's prebuilt release archive and verifies its SHA-256 checksum before running (Linux and macOS runners). New inputs: `output`, `remediation`, `config`, `scan-diff`, `extra-args`, `working-directory`, `release-repo`. Composite `outputs` now declare `value:` mappings, so `findings-count` and `sarif-file` are actually exposed to downstream steps (previously always empty). The download is checksum-verified and retried; `extra-args` rejects (by prefix, so combined shorthand like `-fcsv` is caught too) flags the action manages (`--format`/`--output`/`--config`/`--show-raw`); the assembled command is not echoed (path/extra-args may carry credentials); `scan-diff` is validated and `auto` degrades to a full scan with a warning when the base commit is absent (e.g. a shallow checkout) instead of hard-failing; and the `github` format always writes annotations to stdout even if an output file is configured. The nested `upload-sarif` and all CI workflow actions are SHA-pinned.
- **Pull-request diff scanning in the Action** — for `git` scans, `scan-diff: auto` (default) limits the scan to commits introduced by the event (`pull_request` base..HEAD or `push` before..HEAD) via `--since-commit`, so CI surfaces only newly added secrets. Requires `actions/checkout` with `fetch-depth: 0`.
- **GitHub Actions job summary** — the action writes a findings summary (counts and a per-finding table parsed from SARIF) to `$GITHUB_STEP_SUMMARY`.
- **`github` output format** — `--format github` emits GitHub Actions workflow commands (`::error`/`::warning`/`::notice`) so findings appear as inline annotations on pull requests. The raw secret is never emitted (redacted only), and command data/properties are percent-escaped. New `internal/output/github` formatter with full unit-test coverage.
- **Floating major version tag** — releases now move the `vN` tag (e.g. `v1`) to the latest `vN.x.y` so consumers can pin `uses: HodeTech/Leakwatch@v1`. Pre-releases (tags containing `-`) are skipped.
- **Action self-test workflow** — `.github/workflows/action-test.yml` runs the composite action against fixtures on Linux and macOS and lints all workflows with `actionlint` (which also shellchecks the `run:` scripts).
- **Custom rules are now loaded from `.leakwatch.yaml`** — the documented `custom-rules:` block is finally wired into the scan. Previously `custom.RegisterCustomRules` existed and was tested but never called, so user-defined detectors were silently ignored. Registration is duplicate-safe: a rule whose ID collides with a built-in detector (or another custom rule) is skipped with a warning instead of panicking. (Resolves ROADMAP "Known Gaps" P0 #1.)
- **Inline ignore (`# leakwatch:ignore` / `# leakwatch:ignore:<detector-id>`) is now honored** — the marker is checked on each finding's source line during scanning and ignored findings are dropped before verification, so they never trigger a network call. Repeated occurrences of the same secret are resolved to their own lines, so an ignore on one copy never suppresses a genuine leak elsewhere in the file. The library helpers existed but were never invoked by the engine. (Resolves ROADMAP "Known Gaps" P0 #2.)
- **Line numbers are now reported for findings** — the engine computes the 1-based line of each match per occurrence (from its byte offset within the chunk). Previously every finding reported `line: 0` in JSON/SARIF/CSV/table output, and repeated matches of the same bytes would all have collapsed onto the first occurrence's line. This is also the prerequisite that makes inline ignore correct.
- **`verification.*` config is now bound** — `verification.enabled`, `verification.timeout`, `verification.concurrency`, and `verification.rate-limit` from `.leakwatch.yaml` now drive the verification engine. They were emitted by `leakwatch init` and documented but had no effect. The `--no-verify` flag still takes precedence. (Resolves ROADMAP "Known Gaps" P0 #3.)
- **`filter.exclude-detectors` and `output.severity-threshold` config are now bound** — documented YAML keys that previously no-opped. `--min-severity` still overrides `output.severity-threshold`. (Resolves ROADMAP "Known Gaps" P1 config schema drift, except the optional `slack.*` keys.)
- **`scan repos` now honors all scan configuration** — custom-rules, `verification.*`, `exclude-detectors`, `.leakwatchignore`, and remediation enrichment now apply to multi-repo scans. Previously `scan repos` built its own engine config and silently ignored every one of them. The shared `buildEngineConfig` helper now backs all scan commands.
- **SARIF results carry location-independent `partialFingerprints`** — GitHub Code Scanning tracks an alert across line moves instead of closing and reopening it. (Important now that findings report real line numbers instead of `line: 0`.)

### Changed
- **CI coverage-gate script quoting** — quoted the `bc` command substitution in the coverage check (`ci.yml`) so the new `actionlint`/shellcheck job passes (SC2046).
- **Config validation hardening** — `output.severity-threshold` is validated against the known severity set (a typo no longer silently falls back to "low"); a unit-less `verification.timeout` (e.g. `30`, which YAML decodes as 30 nanoseconds) is rejected with a hint to use a unit; a disabled `verification:` block no longer fails validation on leftover non-positive values; nested config keys are now overridable via environment variables (e.g. `LEAKWATCH_OUTPUT_SEVERITY_THRESHOLD`).
- **`detector.RegisterIfAbsent`** — new atomic check-and-insert used by custom-rule registration to avoid a check-then-register race and the panic on duplicate IDs.
- **Finding IDs include the line number** — disambiguates two findings that share the same redacted value in the same file (e.g. two private keys with identical redaction on different lines).
- **`internal/remediation/guidance.go`** — 13 frequently repeated step/checklist strings extracted to package-level constants. Emitted strings are byte-identical; 100% test coverage preserved.
- **`cmd/imports.go`** — each blank import now carries an inline `// register <plugin>` comment plus a file-level explanation of the ADR-0004 plugin-registration pattern (SonarCloud `godre:S8184`).

### Fixed
- **GitHub stateless (JWT-format) `ghs_` installation tokens are now detected in full** — from April 2026 GitHub began issuing installation tokens (including the Actions `GITHUB_TOKEN`) in a new `ghs_APPID_<jwt>` format: a `ghs_`-prefixed JWT of ~520 characters containing two dots. The previous `gh[orus]_[A-Za-z0-9_]{36,}` pattern had no `.` in its body class, so it truncated such a token at the first dot — and missed it entirely when a base64url `-` appeared before the body reached 36 characters — while the JWT body fell through to the generic `jwt` detector. One secret was reported as two wrong findings (or one wrong one). The `github-oauth-token` detector now captures the whole stateless token as a single `ghs_<base64url>.<base64url>.<base64url>` match while leaving the opaque `gho_`/`ghu_`/`ghr_`/legacy `ghs_` matches and `ghp_` (separate `github-token` detector) unchanged. The `jwt` detector now suppresses a JWT that is the body of a `ghs_` token so the secret is reported exactly once. Redaction still reveals only the trailing four characters; verification is unaffected (a live installation token is reported as a verify error rather than a false "active"/"revoked"). `ghu_` (user-to-server) is intentionally left opaque until GitHub publishes its new format. (60 detector packages / 63 detectors unchanged.)
- **`dbconn` placeholder case-sensitivity bug** — `Password=TODO` and `Password=FIXME` (uppercase) were previously **not** skipped as placeholders even though the placeholder list contained the entries. The lookup lowercased the password but compared against uppercase slice entries, so the two values silently fell through and were reported as findings. The placeholder slice is now lowercased so case-insensitive matching actually works as documented. **User-visible behavior change:** `Password=TODO` no longer produces a finding.

### Tests
- **`detector/dbconn` coverage** raised from 51.5% to 97.0% (CLAUDE.md standard is 95%). New table-driven tests cover ADO.NET parsing, the placeholder list (case-insensitive), `redactADONet`, and the `url.Parse` error path of `redactPassword`.
- **Generated `detectors.js` is guarded against silent detector drops** — a new test pins the web-playground bundle (`site/js/detectors.js`) to the live detector registry, so a detector whose regex is not a single AST-extractable ``regexp.MustCompile(`literal`)`` (e.g. concatenated fragments) fails CI instead of silently vanishing from the playground. Also adds an explicit GitHub `/user` 403 verifier case documenting that a live stateless installation token maps to verify-error, never a false active/revoked.

### Security
- **`action/action.yml` shell injection (SonarCloud `githubactions:S7630`, 8 BLOCKER findings)** — every `${{ inputs.* }}` interpolation moved into an `env:` block; bash args switched from a whitespace-joined string to an array. CWE-94 closed.
- **`action/action.yml` exit code propagation (Gemini code-assist review, high priority)** — the scan step previously swallowed `leakwatch`'s exit code, so the action reported success even when secrets were found. New input `fail-on-findings` (default `true`) controls whether findings fail the step; hard errors (exit ≥ 2) always fail.
- **`Dockerfile`** — base image bumped from `golang:1.24-alpine` (could not build the v1.25.8 go.mod) to `golang:1.25.8-alpine`. `.dockerignore` hardened against secrets, build artifacts, and unused trees.
- **`.github/workflows/release.yml`** — third-party actions pinned to immutable commit SHAs (`actions/checkout` v6.0.0, `actions/setup-go` v6.0.0, `goreleaser/goreleaser-action` v6.4.0). `persist-credentials: false` on checkout.

### Documentation
- Comprehensive doc cleanup aligning all guides, the README, CLAUDE.md, ROADMAP, and CHANGELOG with the actual v1.5.0 state: corrected detector/verifier counts (60 packages / 63 detectors, 51 packages / 54 verifiers), fixed 20+ broken ADR/anchor links (English file names), translated ~18 Mermaid diagrams from Turkish to English, standardized `Status:` fields, corrected vault/jwt verifier categorization, added v1.5.0 "What's New" section, and added a "Known Gaps & Follow-up Work" section to the ROADMAP tracking the items intentionally left for future PRs.

---

## [v1.5.0] - 2026-04-09

### Added
- **ADO.NET (Microsoft SQL Server) connection string** format support in the `dbconn` detector

### Fixed
- **False positive reduction** — improved filtering for lock files (`package-lock.json`, `yarn.lock`, and friends), and test fixtures. (Note: case-insensitive placeholder matching for `TODO`/`FIXME` was intended in this release but was incomplete — fixed under `[Unreleased]`.)
- **ADO.NET connection string parsing** — handles key/value pairs separated by `;` correctly
- **PagerDuty detector** — context-aware detection to reduce false positives in unrelated string matches

### Changed
- **CI pinned to Go 1.25.8** — latest version currently available in GitHub Actions runners

---

## [v1.4.0] - 2026-04-08

### Added
- **Scan summary** — every scan prints a summary to stderr (date, source type, target, files scanned, duration, findings count, verification stats)
- **`leakwatch init` command** — generates a `.leakwatch.yaml` with recommended defaults
- **Colored table output** — severity-colored terminal output (red=critical/high, yellow=medium, blue=low), auto-disabled when writing to a file
- **Rich help messages** — all commands include `Example` sections with practical usage patterns
- **Better error messages** — friendly error messages with help suggestions

### Changed
- **`scan fs` defaults to current directory** — path argument is now optional (defaults to `.`)
- **`.leakwatchignore` CWD fallback** — also searches the current working directory if `.leakwatchignore` is not found alongside the config file

### Security
- Upgraded to **Go 1.25.8** + **go-git v5.17.1** (security fixes, including the idx file DoS vulnerability)

---

## [v1.3.2] - 2026-03-25

### Fixed
- **GoReleaser binary name** — forced lowercase binary name in release artifacts

---

## [v1.3.1] - 2026-03-25

### Added
- **Code of Conduct, issue templates, GitHub Discussions** enabled for the repository

### Changed
- **Homebrew automation** — CI configured with `HOMEBREW_TAP_TOKEN` so GoReleaser can push to the Homebrew tap automatically on release

---

## [v1.3.0] - 2026-03-25

### Added
- **51 new secret detectors** bringing the total to 60 detector packages (63 detector registrations)
  - Sprint 1: OpenAI, Anthropic, GitLab, SendGrid, NPM, Discord, Telegram, Redis, Snowflake, Datadog
  - Sprint 2: Hugging Face, DeepSeek, GCP, Azure (Storage + Entra), Okta, Twilio, Mailgun, Vault, Grafana, PagerDuty, CircleCI, GitHub OAuth
  - Sprint 3: PyPI, RubyGems, Docker Hub, DigitalOcean, Heroku, Vercel, New Relic, Sentry, Shopify, Supabase, Cloudflare, Notion, Linear, Figma, Airtable
  - Sprint 4: Terraform, Databricks, Bitbucket, Coinbase, Infura, RabbitMQ, FTP, LDAP, Auth0, LaunchDarkly, Snyk, SonarCloud, Doppler, MS Teams, Postmark
- **54 verifiers (51 packages)** — verification coverage increased to ~85.7% (54/63)
  - V-1 (Tier 1 P0): OpenAI, Anthropic, GitLab, SendGrid, DigitalOcean, Cloudflare, Heroku, New Relic, Telegram, Discord, Notion
  - V-2 (Tier 1 P1): Sentry, Vercel, NPM, PyPI, Grafana, PagerDuty, Databricks, Linear, Figma, Airtable, HuggingFace, CircleCI
  - V-3 (Tier 1 P2): DockerHub, Doppler, Snyk, SonarCloud, Postmark, Terraform, LaunchDarkly, Mailgun, Coinbase, Infura
  - V-4 (Tier 2): Okta, Shopify, Stripe (live+test), Twilio, Bitbucket, Auth0, Datadog, RubyGems, DeepSeek, Supabase
  - V-5 (Tier 2+3): GitHub OAuth, Teams Webhook, Azure Storage, Azure Entra, GCP, Snowflake, RabbitMQ
  - Verification types: **Live API verification** (API call to provider) and **Format validation** (structural check without network call, used for Azure Storage, Azure Entra, GCP Service Account, Snowflake, RabbitMQ)
  - Per-provider rate limiting for all verifiers (configurable)
- **Remediation guidance** for all detector types (previously planned for the `v1.1.0` slot — shipped together with `v1.3.0`)
- **Slack workspace scanning** — `scan slack` command with channel/date/DM/file filtering (previously planned for the `v1.2.0` slot — shipped together with `v1.3.0`)
- **APISIX key patterns** added to the generic API key detector

> **Note:** The `v1.1.0` (Remediation) and `v1.2.0` (Slack) phases were merged into `main` but never released as standalone git tags. Their features were rolled up into the `v1.3.0` release.

---

## [v1.2.0] - 2026-03-24 _(rolled into v1.3.0; no git tag)_

### Added
- **Slack Workspace Scanning** — scan Slack messages, channels, and files for secrets
- `scan slack` command with Bot Token authentication (`--token` or `LEAKWATCH_SLACK_TOKEN`)
- Channel filtering (`--channels`, `--exclude-channels`), date filtering (`--since`)
- DM scanning opt-in (`--include-dms`), file scanning (`--include-files`)
- Rate-limited Slack API pagination (configurable with `--rate-limit`)
- `SourceMetadata` extended with Slack fields (Channel, ChannelName, MessageUser, MessageTS, ThreadTS)

---

## [v1.1.0] - 2026-03-24 _(rolled into v1.3.0; no git tag)_

### Added
- **Remediation Guidance** — actionable rotation/revocation instructions for all detectors
- `--remediation` flag on all scan commands to include guidance in output
- Remediation registry with guidance for all built-in detector types (AWS, GitHub, Slack, Stripe, JWT, DB Connection, Private Key, Generic, and more)
- SARIF output includes `help` and `helpUri` properties on rules when remediation is enabled
- CSV output includes `remediation` column
- Table output includes `REMEDIATION` column

---

## [v1.0.0] - 2026-03-24

### Added

#### Scan Sources
- Filesystem scanning with `scan fs` command
- Git repository scanning with `scan git` command (full history + diff-based)
- Container image scanning with `scan image` command (layer-by-layer, daemonless)
- AWS S3 bucket scanning with `scan s3` command
- Google Cloud Storage scanning with `scan gcs` command
- Parallel multi-repo scanning with `scan repos` command

#### Secret Detectors
- AWS Access Key ID detector
- GitHub Personal Access Token detector
- Slack Bot/User Token detector
- Slack Webhook URL detector
- Stripe Live API Key detector
- Stripe Test API Key detector
- JWT detector
- Database Connection String detector (PostgreSQL, MySQL, MongoDB, Redis)
- Private Key detector (RSA, SSH, DSA, EC, PGP)
- Generic API Key detector (with entropy filtering)
- YAML custom rule support for user-defined detectors

#### Detection Engine
- Aho-Corasick keyword pre-filtering for O(n) multi-pattern matching
- Shannon entropy analysis with configurable thresholds
- Hybrid detection pipeline: keyword pre-filter → regex validation → entropy check
- Worker pool with bounded concurrency and graceful shutdown
- Context cancellation propagation throughout the pipeline

#### Secret Verification
- Verifier interface with rate-limited concurrent verification engine
- AWS STS `GetCallerIdentity` verifier
- GitHub API `/user` verifier
- `--only-verified` flag to show only active secrets
- `--no-verify` flag to disable verification

#### Output Formats
- JSON output with `omitempty` and `ShowRaw` security control
- SARIF v2.1.0 output for GitHub Code Scanning integration
- CSV output for spreadsheet analysis
- Human-readable terminal table output
- Severity serialized as string in JSON (`"critical"`, not `3`)

#### Filtering & Ignoring
- `.leakwatchignore` file support with glob patterns (including `**`)
- Inline ignore comments (`# leakwatch:ignore` and `# leakwatch:ignore:<detector-id>`)
- `--min-severity` flag for severity threshold filtering
- File size, binary file, and extension filtering

#### Configuration
- Hierarchical configuration: CLI flags > env vars > project YAML > global YAML > defaults
- `.leakwatch.yaml` configuration file
- `LEAKWATCH_` environment variable prefix
- Git-specific flags: `--since`, `--since-commit`, `--branch`, `--depth`
- Cloud-specific flags: `--prefix`, `--region`, `--project`

#### CI/CD & Distribution
- GitHub Actions (`action/action.yml`) with SARIF upload support
- Pre-commit hook (`.pre-commit-hooks.yaml`)
- Dockerfile (multi-stage, non-root, Alpine-based)
- Homebrew formula (`Formula/leakwatch.rb`)
- GoReleaser configuration for cross-platform builds
- CI pipeline: test (Go 1.23/1.24 matrix), lint, security scan, 80% coverage gate

#### Documentation
- 6 user guides: Getting Started, Configuration, CI/CD Integration, Custom Rules, Container Scanning, Cloud Scanning
- 8 Architecture Decision Records (ADRs)
- Architecture design document with interface definitions
- Competitive analysis and technology decisions
- Code review standards (50+ checklist items, 12 zero-tolerance rules)
- Release and distribution standards
- Development standards (coding, testing, CI/CD)
- Documentation standards (Mermaid diagrams, templates)

### Security
- `ShowRaw` defense-in-depth: raw secret content stripped by default at formatter level
- URL credential sanitization before logging
- Path traversal protection in filesystem and container sources
- Temp directory cleanup for cloned repositories (`Close()` method)
- `secret_scanning.yml` to exclude test fixtures from GitHub Push Protection

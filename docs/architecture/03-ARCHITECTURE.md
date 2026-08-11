# Leakwatch - Detailed Architecture Design

> **Document Version:** 1.1
> **Date:** 2026-05-22
> **Status:** Approved

---

## 1. Architecture Overview

Leakwatch is built on a pipeline-based architecture. Data flows through a series of well-defined stages from source (Source) to output (Output). Each stage can be independently tested, scaled, and replaced.

```mermaid
flowchart LR
    subgraph Sources["Sources"]
        S1[Git]
        S2[Filesystem]
        S3[Container]
        S4["S3 (v2)"]
        S5[GCS]
        S6[Slack]
    end

    subgraph Engine["Detection Engine"]
        E1[Aho-Corasick]
        E2[Regex Validation]
        E3[Entropy Analysis]
        E4[Custom Rules]
    end

    subgraph Verifiers["Verification (39 direct-live + 9 context-required + 6 format-only)"]
        V1[AWS STS]
        V2[GitHub API]
        V3[Slack API]
        V4[Stripe, context & format checks]
    end

    subgraph Output["Output"]
        O1[JSON]
        O2[SARIF]
        O3[CSV]
        O4[Table]
    end

    Sources -->|Chunks| Chunker[Chunker]
    Chunker --> Engine
    Engine --> Verifiers
    Verifiers --> Filter["Filter & Output"]
    Filter --> Output
```

---

## 2. Core Interfaces

Leakwatch's extensibility is built on well-defined Go interfaces. These interfaces are the "contracts" of the system.

```mermaid
classDiagram
    class Source {
        <<interface>>
        +Type() string
        +Chunks(ctx) chan Chunk
        +Validate(ctx context.Context) error
    }

    class Detector {
        <<interface>>
        +ID() string
        +Description() string
        +Keywords() []string
        +Scan(ctx, data) []RawFinding
        +Severity() Severity
    }

    class Verifier {
        <<interface>>
        +Type() string
        +Verify(ctx, raw detector.RawFinding) finding.VerificationResult
    }

    class Formatter {
        <<interface>>
        +Format(w, findings) error
        +FileExtension() string
    }

    class Chunk {
        +Data []byte
        +SourceMetadata SourceMetadata
    }

    class RawFinding {
        +DetectorID string
        +Raw []byte
        +Redacted string
    }

    class Finding {
        +ID string
        +DetectorID string
        +Severity Severity
        +Redacted string
        +SourceMetadata SourceMetadata
        +Verification VerificationResult
        +Entropy float64
    }

    Source --> Chunk : produces
    Detector --> RawFinding : produces
    Verifier --> Finding : enriches
    Formatter --> Finding : formats
    RawFinding --> Finding : transforms into

    GitSource ..|> Source
    FilesystemSource ..|> Source
    ContainerSource ..|> Source
    S3Source ..|> Source
    GCSSource ..|> Source
    SlackSource ..|> Source

    AWSDetector ..|> Detector
    GitHubDetector ..|> Detector
    GenericDetector ..|> Detector

    AWSVerifier ..|> Verifier
    GitHubVerifier ..|> Verifier

    JSONFormatter ..|> Formatter
    SARIFFormatter ..|> Formatter
    CSVFormatter ..|> Formatter
```

### 2.1 Source Interface

```go
// Source represents a data source to be scanned.
// Each source type (Git, filesystem, container) implements this interface.
type Source interface {
    // Type returns the source type (e.g., "git", "filesystem", "container").
    Type() string

    // Chunks sends data chunks to be scanned over a channel.
    // The channel is closed when the context is cancelled.
    Chunks(ctx context.Context) <-chan Chunk

    // Validate checks that the source is accessible and valid.
    Validate(ctx context.Context) error
}

// Chunk represents the smallest unit of data to be scanned.
type Chunk struct {
    // Data is the raw content to be scanned.
    Data []byte

    // SourceMetadata is the context information identifying where the finding came from.
    SourceMetadata SourceMetadata
}

// SourceMetadata describes the origin of a chunk.
type SourceMetadata struct {
    // Fields specific to the source type
    SourceType string // "git", "filesystem", "container"

    // Git-specific
    Repository string
    Commit     string
    Author     string
    Email      string
    Date       time.Time
    Branch     string

    // File-specific
    FilePath string
    Line     int

    // Container-specific
    Image    string
    Layer    string
    LayerIdx int
}
```

### 2.2 Detector Interface

```go
// Detector represents a component that detects a specific secret type.
type Detector interface {
    // ID returns the detector's unique identifier (e.g., "aws-access-key-id").
    ID() string

    // Description returns the detector's human-readable description.
    Description() string

    // Keywords returns keywords for Aho-Corasick pre-filtering.
    // If empty, pre-filtering is skipped and regex is applied to every chunk.
    Keywords() []string

    // Scan scans the given data and returns potential secrets found.
    Scan(ctx context.Context, data []byte) []RawFinding

    // Severity returns the default severity level for this detector's findings.
    Severity() Severity
}

// RawFinding represents an unverified raw finding.
type RawFinding struct {
    DetectorID string
    Raw        []byte   // The discovered secret data
    RawV2      []byte   // Optional: second part of the secret (e.g., secret key)
    Redacted   string   // Masked version (for logging)
    ExtraData  map[string]string // Additional context information
}
```

### 2.3 Verifier Interface

```go
// Verifier represents a component that validates a secret's authenticity.
// Defined in internal/verifier/verifier.go.
type Verifier interface {
    // Type returns which detector ID this verifier handles.
    // Must match the corresponding Detector.ID() value.
    Type() string

    // Verify checks whether the found secret is valid/active.
    // May make network calls, so it can be cancelled via context.
    Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult
}

// VerificationResult represents the verification outcome.
type VerificationResult struct {
    Status    VerificationStatus
    Message   string           // Human-readable description
    ExtraData map[string]string // Additional information obtained during verification
}

// VerificationStatus represents the verification state.
type VerificationStatus int

const (
    StatusUnverified      VerificationStatus = iota // Verification not performed
    StatusVerifiedActive                             // Verified: secret is active
    StatusVerifiedInactive                           // Verified: secret is inactive
    StatusVerifyError                                // Error during verification
)
```

### 2.4 Formatter Interface

```go
// Formatter represents a component that outputs findings in a specific format.
type Formatter interface {
    // Format writes findings to the specified writer.
    Format(w io.Writer, findings []Finding) error

    // FileExtension returns the file extension for this format.
    FileExtension() string
}
```

### 2.5 Unified Finding Model

```go
// Finding represents a fully enriched finding.
// It is the final output of the pipeline.
type Finding struct {
    // Identity
    ID         string    `json:"id"`
    DetectorID string    `json:"detector_id"`
    Severity   Severity  `json:"severity"`

    // Secret data
    Raw      string `json:"-"`        // Dedicated opt-in wire type only
    Redacted string `json:"redacted"` // Masked

    // Location
    SourceMetadata SourceMetadata `json:"source"`

    // Verification
    Verification VerificationResult `json:"verification"`

    // Timestamp
    DetectedAt time.Time `json:"detected_at,omitempty"` // Custom marshal omits zero

    // Entropy
    Entropy           float64 `json:"entropy,omitempty"`
    EntropyCalculated bool    `json:"-"` // Preserves a calculated 0.0 on the wire

    // Additional context
    ExtraData map[string]string `json:"-"` // Dedicated opt-in wire type only
}

// SetEntropy marks a value as calculated, including a legitimate 0.0.
func (f *Finding) SetEntropy(value float64)

// Severity represents the finding severity level.
type Severity int

const (
    SeverityLow      Severity = iota
    SeverityMedium
    SeverityHigh
    SeverityCritical
)
```

The custom JSON contract omits absent entropy and zero `DetectedAt`, but emits a
legitimately calculated entropy of `0.0`. `Raw` and `ExtraData` remain
type-level excluded; the JSON formatter's explicit `--show-raw` wire type is the
only path that can add them.

---

### 2.6 Component Interaction Sequence

The following sequence diagram shows how components interact during a single scan operation:

```mermaid
sequenceDiagram
    participant CLI
    participant Engine
    participant Source
    participant Worker
    participant Detector
    participant Verifier
    participant Formatter

    CLI->>Engine: Scan(config)
    Engine->>Source: Chunks(ctx)
    loop For each chunk
        Source-->>Engine: Chunk{data, metadata}
        Engine->>Worker: Send to jobs channel
        Worker->>Worker: Aho-Corasick pre-filtering
        alt Keyword matched
            Worker->>Detector: Scan(ctx, data)
            Detector-->>Worker: []RawFinding
            Worker-->>Engine: Write to results channel
            Note over Worker: Entropy is calculated and attached;<br/>opt-in heuristic findings are threshold-gated
        end
    end
    opt Verification enabled
        Engine->>Verifier: Verify(ctx, finding)
        Verifier-->>Engine: VerificationResult
    end
    Engine->>Formatter: Format(w, findings)
    Formatter-->>CLI: Output (JSON/SARIF/CSV)
```

---

## 3. Scan Engine Detailed Design

### 3.1 Worker Pool Model

```mermaid
flowchart TD
    Source["SOURCE\n(chunks channel)"] --> Jobs["JOBS CHANNEL\n(buffered chan)"]
    Jobs --> W1["Worker 1\nAC Match → Regex → Entropy policy"]
    Jobs --> W2["Worker 2..N-1\nAC Match → Regex → Entropy policy"]
    Jobs --> WN["Worker N\nAC Match → Regex → Entropy policy"]
    W1 --> Results["RESULTS CHANNEL\n(buffered chan)"]
    W2 --> Results
    WN --> Results
    Results --> Verify["VERIFICATION\n(optional, async)"]
    Verify --> Output["FILTER & OUTPUT"]
```

### 3.2 Engine Configuration

```go
// Config holds the scan engine configuration (internal/engine/engine.go).
type Config struct {
    // Concurrency controls the number of worker goroutines.
    // Channel buffers are sized as Concurrency × 2.
    Concurrency int

    // Detection
    Detectors        []detector.Detector
    EnableEntropy    bool
    // EntropyThreshold gates only heuristic detectors that explicitly opt in;
    // structural provider detectors remain independent of entropy.
    EntropyThreshold float64 // Default: 4.0
    ShowRaw          bool    // Expose raw secret content on Finding.Raw

    // Optional clock override (for deterministic tests)
    Clock func() time.Time

    // Verification
    VerifierConfig verifier.Config
    Verifiers      []verifier.Verifier
    OnlyVerified   bool // If true, suppress unverified findings

    // Filtering
    MinSeverity finding.Severity // Minimum severity to include
}
```

### 3.3 Engine Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Initialization

    state Initialization {
        [*] --> LoadDetectors: Load from registry
        LoadDetectors --> CompileAC: Compile Aho-Corasick automaton
        CompileAC --> CreatePool: Create worker pool
        CreatePool --> CreateChannels: Create channels
    }

    Initialization --> Scanning

    state Scanning {
        [*] --> ReadChunk: Read from Source.Chunks() channel
        ReadChunk --> SendToJobs: Send to jobs channel
        SendToJobs --> ParallelScan
        state ParallelScan {
            [*] --> ACPreFilter: Aho-Corasick pre-filtering
            ACPreFilter --> DetectorScan: Call matching detectors' Scan()
            DetectorScan --> EntropyCalc: Score and opt-in heuristic gate
            EntropyCalc --> WriteResult: Write to results channel
        }
    }

    Scanning --> Verification: Optional

    state Verification {
        [*] --> FindVerifier: Find matching Verifier
        FindVerifier --> CallVerify: Call Verify() (rate-limited)
        CallVerify --> Enrich: Enrich Finding
    }

    Verification --> Output

    state Output {
        [*] --> AllowlistFilter: Apply allowlist/ignore
        AllowlistFilter --> VerifiedFilter: --only-verified filter
        VerifiedFilter --> SeverityFilter: Severity filter
        SeverityFilter --> Format: Output via Formatter.Format()
    }

    Output --> [*]
```

---

## 4. Plugin Registration Mechanism

### 4.1 Compile-Time Registration Pattern

```go
// internal/detector/registry.go

var (
    mu        sync.RWMutex
    detectors = make(map[string]Detector)
)

// Register registers a detector in the central registry.
// Each detector package calls this function in its init() function.
func Register(d Detector) {
    mu.Lock()
    defer mu.Unlock()
    if _, exists := detectors[d.ID()]; exists {
        panic("duplicate detector ID: " + d.ID())
    }
    detectors[d.ID()] = d
}

// All returns all registered detectors.
func All() []Detector {
    mu.RLock()
    defer mu.RUnlock()
    result := make([]Detector, 0, len(detectors))
    for _, d := range detectors {
        result = append(result, d)
    }
    return result
}
```

### 4.2 Detector Registration Example

```go
// internal/detector/aws.go

func init() {
    Register(&AWSAccessKeyID{})
    Register(&AWSSecretAccessKey{})
}

type AWSAccessKeyID struct{}

func (d *AWSAccessKeyID) ID() string          { return "aws-access-key-id" }
func (d *AWSAccessKeyID) Description() string  { return "AWS Access Key ID" }
func (d *AWSAccessKeyID) Keywords() []string   { return []string{"AKIA", "ABIA", "ACCA", "ASIA"} }
func (d *AWSAccessKeyID) Severity() Severity   { return SeverityCritical }

func (d *AWSAccessKeyID) Scan(ctx context.Context, data []byte) []RawFinding {
    // AWS Access Key ID pattern: AKIA[0-9A-Z]{16}
    re := regexp.MustCompile(`(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`)
    matches := re.FindAll(data, -1)

    findings := make([]RawFinding, 0, len(matches))
    for _, match := range matches {
        findings = append(findings, RawFinding{
            DetectorID: d.ID(),
            Raw:        match,
            Redacted:   string(match[:4]) + "****" + string(match[len(match)-4:]),
        })
    }
    return findings
}
```

### 4.3 Activation via Blank Import

```go
// main.go or cmd/root.go

import (
    // Register detectors
    _ "github.com/HodeTech/leakwatch/internal/detector/aws"
    _ "github.com/HodeTech/leakwatch/internal/detector/generic"
    _ "github.com/HodeTech/leakwatch/internal/detector/privatekey"
    _ "github.com/HodeTech/leakwatch/internal/detector/github"
    _ "github.com/HodeTech/leakwatch/internal/detector/slack"
    _ "github.com/HodeTech/leakwatch/internal/detector/stripe"
    _ "github.com/HodeTech/leakwatch/internal/detector/jwt"
    _ "github.com/HodeTech/leakwatch/internal/detector/dbconn"
    _ "github.com/HodeTech/leakwatch/internal/detector/custom"

    // Register sources
    _ "github.com/HodeTech/leakwatch/internal/source/git"
    _ "github.com/HodeTech/leakwatch/internal/source/filesystem"
    _ "github.com/HodeTech/leakwatch/internal/source/container"
    _ "github.com/HodeTech/leakwatch/internal/source/s3"
    _ "github.com/HodeTech/leakwatch/internal/source/gcs"
    _ "github.com/HodeTech/leakwatch/internal/source/slack"

    // Register verifiers
    _ "github.com/HodeTech/leakwatch/internal/verifier/aws"
    _ "github.com/HodeTech/leakwatch/internal/verifier/github"
)
```

---

## 5. Source Implementations

### 5.1 Git Source Flow Diagram

```mermaid
flowchart TD
    A["git.PlainOpen(path)\nor git.Clone(url)"] --> B["repo.Log(LogOptions{\n  Since: sinceFlag,\n  Order: CommitterTime\n})"]
    B --> C{"For each\ncommit"}
    C --> D["commit.Tree()"]
    D --> E["tree.Files()"]
    E --> F{"For each\nfile"}
    F --> G["file.Contents()"]
    G --> H["Chunk{\n  Data: contents,\n  SourceMetadata: {repo, commit, author, date, filePath}\n}"]
    H --> I[("chunks channel")]
    I --> C
```

### 5.2 Filesystem Source

```go
// filepath.WalkDir based scanning with io/fs
func (s *FilesystemSource) Chunks(ctx context.Context) <-chan Chunk {
    ch := make(chan Chunk, s.bufferSize)
    go func() {
        defer close(ch)
        filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
            select {
            case <-ctx.Done():
                return ctx.Err()
            default:
            }

            if err != nil || d.IsDir() {
                return nil
            }

            // Filtering: size, extension, .leakwatchignore
            if s.shouldSkip(path, d) {
                return nil
            }

            data, err := os.ReadFile(path)
            if err != nil {
                return nil
            }

            ch <- Chunk{
                Data: data,
                SourceMetadata: SourceMetadata{
                    SourceType: "filesystem",
                    FilePath:   path,
                },
            }
            return nil
        })
    }()
    return ch
}
```

### 5.3 Container Image Source

```mermaid
flowchart TD
    A["crane.Pull(imageName)"] --> B["img.Layers()"]
    B --> C{"For each\nlayer"}
    C --> D["layer.Uncompressed()"]
    D --> E["tar.NewReader(reader)"]
    E --> F{"For each file\n(tar entry)"}
    F --> G["Chunk{\n  Data: fileContents,\n  SourceMetadata: {image, layer, layerIdx, filePath}\n}"]
    G --> H[("chunks channel")]
    H --> C
```

---

## 6. Detection Engine Detail

### 6.1 Aho-Corasick + Regex Hybrid Strategy

```mermaid
flowchart TD
    A["Incoming Chunk (data)"] --> B["Aho-Corasick Pre-Filtering\nO(n) — single pass"]
    B --> C{"Match\nfound?"}
    C -->|"No"| D["Skip\n(90%+ chunks eliminated here)"]
    C -->|"Yes"| E["Which keyword(s) matched?"]
    E --> F["Call only matching detectors'\nScan() method (regex)"]
    F --> G{"Finding\nexists?"}
    G -->|"No"| H[Skip]
    G -->|"Yes"| I["Calculate Shannon entropy\n(if EnableEntropy = true)"]
    I --> J{"Detector opts into\nentropy gating?"}
    J -->|"No"| K["Finding → Results channel"]
    J -->|"Yes, score meets threshold"| K
    J -->|"Yes, score below threshold"| H
```

> **Entropy policy:** The engine attaches the computed value to every finding for review. The configured threshold suppresses only heuristic detectors that explicitly opt into entropy gating — currently `generic-api-key`. Structural provider detectors such as AWS and GitHub never depend on this threshold. Custom rules apply their own independent per-rule `entropy` threshold.

### 6.2 Shannon Entropy Calculation

```go
// entropy/shannon.go

// Calculate computes the Shannon entropy of the given byte slice.
// The result ranges from 0.0 (perfectly uniform) to ~8.0 (perfectly random).
func Calculate(data []byte) float64 {
    if len(data) == 0 {
        return 0.0
    }

    // Count character frequencies
    freq := make(map[byte]float64)
    for _, b := range data {
        freq[b]++
    }

    // Shannon entropy formula: H = -Σ p(x) * log2(p(x))
    length := float64(len(data))
    entropy := 0.0
    for _, count := range freq {
        p := count / length
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }
    return entropy
}

// Recommended threshold values:
// - Hex character set:    > 3.0 (high entropy)
// - Base64 character set: > 4.5 (high entropy)
// - General:              > 4.0 (high entropy)
```

---

## 7. Verification Subsystem

### 7.1 Rate Limiting and Security

```go
type VerificationEngine struct {
    verifiers    map[string]Verifier
    rateLimiter  *rate.Limiter        // golang.org/x/time/rate
    timeout      time.Duration
    concurrency  int
    enabled      bool
}

// Security rules:
// 1. Verified credentials are NEVER logged
// 2. Rate limiting is mandatory — to avoid overloading APIs
// 3. Timeout is mandatory — to avoid waiting on unresponsive APIs
// 4. Can be disabled by the user (--no-verify)
//
// Verification-result caching (re-verifying the same secret would be
// skipped) is NOT implemented today — the engine holds no cache field, so
// every finding triggers its own live API call. This is planned for
// Phase 11 (see docs/05-ROADMAP.md).
```

### 7.2 AWS Verification Example

```go
// verifier/aws.go

func (v *AWSVerifier) Verify(ctx context.Context, finding RawFinding) VerificationResult {
    accessKeyID := string(finding.Raw)
    secretKey := string(finding.RawV2)

    if secretKey == "" {
        return VerificationResult{
            Status:  StatusUnverified,
            Message: "Secret Access Key not found, cannot verify",
        }
    }

    // AWS STS GetCallerIdentity — does not require IAM permissions
    cfg, err := config.LoadDefaultConfig(ctx,
        config.WithCredentialsProvider(
            credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, ""),
        ),
    )
    if err != nil {
        return VerificationResult{Status: StatusVerifyError, Message: err.Error()}
    }

    client := sts.NewFromConfig(cfg)
    result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
    if err != nil {
        return VerificationResult{
            Status:  StatusVerifiedInactive,
            Message: "Key is invalid or disabled",
        }
    }

    return VerificationResult{
        Status:  StatusVerifiedActive,
        Message: fmt.Sprintf("Active key: account=%s, ARN=%s", *result.Account, *result.Arn),
        ExtraData: map[string]string{
            "account": *result.Account,
            "arn":     *result.Arn,
        },
    }
}
```

---

## 8. Configuration Hierarchy

Configuration managed by Viper is applied according to the following priority order (descending priority from top to bottom):

```
1. Command-line flags               (highest priority)
   --concurrency=8

2. Environment variables
   LEAKWATCH_CONCURRENCY=8

3. Project configuration file
   .leakwatch.yaml (in working directory)

4. Global configuration file
   ~/.leakwatch.yaml

5. Default values                    (lowest priority)
   concurrency: runtime.NumCPU()
```

### 8.1 Configuration File Schema (.leakwatch.yaml)

```yaml
# Scan configuration
scan:
  concurrency: 8              # Number of workers
  max-file-size: 10485760     # 10MB

# Detection configuration
detection:
  entropy:
    enabled: true
    threshold: 4.0

# Verification configuration
verification:
  enabled: true
  timeout: 10s
  concurrency: 4
  rate-limit: 10.0

# Filtering
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.lock"
    - "go.sum"
  exclude-detectors: []

# Output configuration
output:
  format: json                 # json, sarif, csv, table, github
  file: ""                     # If empty, write to stdout
  show-raw: false              # Show secret content
  severity-threshold: low      # Minimum severity level

# Custom rules
custom-rules:
  - id: "internal-api-key"
    description: "Internal API Key"
    regex: 'INTERNAL_[A-Z0-9]{32}'
    keywords: ["INTERNAL_"]
    severity: high
    entropy: 3.5
```

> This example is bound field-for-field against `internal/config/config.go`. There is no `scan.chunk-size`, `detection.detectors.{enabled,disabled}`, or `filter.only-verified` key in the current schema — `--only-verified` and `--exclude-detectors` are scan-command flags, not `.leakwatch.yaml` keys (`filter.exclude-detectors` is the YAML equivalent of `--exclude-detectors`). See [Configuration Guide](../guides/configuration.md) for the authoritative schema reference.

---

## 9. Filtering System

### 9.1 .leakwatchignore

Compatible with Git's `.gitignore` format, defines files and paths to exclude from secret scanning:

```
# Test files
*_test.go
test/**
tests/**
__tests__/**

# Dependencies
vendor/
node_modules/
go.sum
package-lock.json
yarn.lock

# Documentation
docs/**
*.md

# Build outputs
dist/
build/
bin/

# Specific files
.env.example
config.example.yaml
```

### 9.2 Inline Ignore

To exclude specific lines from scanning:

```python
API_KEY = "AKIA1234EXAMPLE567890"  # leakwatch:ignore
PASSWORD = "test123"  # leakwatch:ignore:aws-access-key-id
```

---

## 10. Error Handling and Resilience

### 10.1 Error Strategy

| Error Type | Strategy |
|-----------|----------|
| Source inaccessible (repo/file not found) | Fatal — exit immediately |
| Single file unreadable | Warn, skip, continue |
| Verification error (network/timeout) | Mark as VerifyError, continue |
| Rate limit exceeded | Retry with exponential backoff |
| Insufficient memory | Reduce chunk size, warn |

### 10.2 Structured Logging

```go
// Go 1.21+ log/slog package
slog.Info("scan started",
    "source", "git",
    "repository", repoPath,
    "concurrency", config.Concurrency,
)

slog.Warn("skipping file",
    "path", filePath,
    "reason", "size limit exceeded",
    "size", fileSize,
    "limit", config.MaxFileSize,
)
```

---

## 11. Security Design Principles

1. **Secrets are never logged** — Discovered secrets are only logged in redacted form
2. **Least privilege** — Only read-only API calls are used for verification (e.g., STS GetCallerIdentity)
3. **Secrets are not cached** — Verified secrets are not written to disk
4. **Secure exit codes** — Non-zero exit code when secrets are found (CI/CD integration)
5. **Dependency security** — Regular vulnerability scanning with `govulncheck`
6. **Rate limiting** — Mandatory rate limiting on verification API calls

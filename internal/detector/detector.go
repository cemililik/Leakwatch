// Package detector defines secret detection interfaces.
package detector

import (
	"context"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Detector represents a component that detects a specific secret type.
type Detector interface {
	// ID returns the unique identifier (e.g., "aws-access-key-id").
	ID() string

	// Description returns a human-readable description.
	Description() string

	// Keywords returns Aho-Corasick pre-filter keywords.
	// If empty, pre-filtering is skipped and regex is applied to every chunk.
	Keywords() []string

	// Scan scans the given data and returns potential secret findings.
	Scan(ctx context.Context, data []byte) []RawFinding

	// Severity returns the default severity for findings from this detector.
	Severity() finding.Severity
}

// OverlapFallback is an optional detector contract for broad contextual
// detectors. When an authoritative provider detector reports an intersecting
// byte range in the same source chunk at equal or greater severity, the engine
// suppresses the fallback finding and preserves the provider-specific
// verification and remediation. Implementations must return findings in a
// bounded set because the engine briefly retains fallback candidates until all
// authoritative detectors have scanned that chunk.
type OverlapFallback interface {
	Detector
	FallbackOnSpecializedOverlap() bool
}

// OverlapAuthority is an optional detector contract for built-in,
// provider-specific detectors that may replace a broad OverlapFallback finding
// at the same source bytes. Custom and heuristic detectors must not implement
// this contract: overlap alone does not make a finding more authoritative.
type OverlapAuthority interface {
	Detector
	AuthoritativeOnOverlap() bool
}

// RawFinding represents an unverified raw finding.
type RawFinding struct {
	DetectorID string
	Raw        []byte
	RawV2      []byte
	Redacted   string
	ExtraData  map[string]string
	// ByteStart and ByteEnd identify Raw's exact half-open byte span in the
	// scanned chunk. A zero/zero span means "not provided" for backward
	// compatibility. The engine validates both bounds and bytes before trusting
	// the span, then falls back to legacy raw-value searching when absent or
	// invalid.
	ByteStart int
	ByteEnd   int
}

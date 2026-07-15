// Package mailgun provides a Mailgun API Key secret detector.
package mailgun

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	mailgunKeyPattern = regexp.MustCompile(`key-[a-f0-9]{32}`)
	// mailgunContextPattern requires a Mailgun-specific context word to be
	// present anywhere in the scanned data before a key-<32 hex> match is
	// reported. Without this gate, the bare "key-" + 32 lowercase hex chars
	// shape collides with unrelated identifiers (cache keys, checksums,
	// license/feature-flag IDs, Terraform/K8s resource IDs), producing
	// Critical-severity false positives. Mirrors the context-gating pattern
	// already used by okta and pagerduty in the same batch (see review
	// section 04-detectors-d3.md HIGH finding "mailgun_key.go:13").
	mailgunContextPattern = regexp.MustCompile(`(?i)mailgun`)
)

// Detector detects Mailgun API Keys.
type Detector struct{}

// ID returns the unique identifier of the Mailgun API Key detector.
func (d *Detector) ID() string { return "mailgun-api-key" }

// Description returns a human-readable description of the Mailgun API Key detector.
func (d *Detector) Description() string { return "Mailgun API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Mailgun API Key detection.
func (d *Detector) Keywords() []string { return []string{"mailgun", "MAILGUN", "key-"} }

// Severity returns the default severity level for Mailgun API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Mailgun API Key patterns. A match is only
// reported when the data also contains Mailgun-specific context (the word
// "mailgun", case-insensitively) — the bare key-<32 hex> shape alone is too
// generic to safely report as a Critical secret.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	if !mailgunContextPattern.Match(data) {
		return nil
	}

	matches := mailgunKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		redacted := "key-****" + string(match[len(match)-4:])
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

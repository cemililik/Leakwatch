// Package notion provides a Notion Internal Integration Token secret detector.
package notion

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	// ntnPattern matches the newer ntn_ prefix tokens.
	ntnPattern = regexp.MustCompile(`ntn_[A-Za-z0-9]{43,}`)

	// secretPattern matches the legacy secret_ prefix tokens.
	// Requires "notion" context keyword to avoid false positives.
	secretPattern = regexp.MustCompile(`secret_[A-Za-z0-9]{43,}`)
)

// Detector detects Notion Internal Integration Tokens.
type Detector struct{}

// ID returns the unique identifier of the Notion Token detector.
func (d *Detector) ID() string { return "notion-token" }

// Description returns a human-readable description of the Notion Token detector.
func (d *Detector) Description() string { return "Notion Internal Integration Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Notion Token detection.
func (d *Detector) Keywords() []string { return []string{"ntn_", "secret_"} }

// Severity returns the default severity level for Notion Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Notion Internal Integration Token patterns.
// For tokens with the ntn_ prefix, matching is direct.
// For tokens with the legacy secret_ prefix, a "notion" context keyword must be present.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	var findings []detector.RawFinding

	// Match ntn_ tokens directly.
	for _, match := range ntnPattern.FindAll(data, -1) {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactBytes(match),
		})
	}

	// Match secret_ tokens only if a Notion context keyword is present.
	if detector.HasAnyKeyword(data, "notion") {
		for _, match := range secretPattern.FindAll(data, -1) {
			findings = append(findings, detector.RawFinding{
				DetectorID: d.ID(),
				Raw:        bytes.Clone(match),
				Redacted:   detector.RedactBytes(match),
			})
		}
	}

	return findings
}

func init() {
	detector.Register(&Detector{})
}

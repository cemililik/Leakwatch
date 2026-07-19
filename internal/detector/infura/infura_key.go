// Package infura provides an Infura API Key secret detector.
package infura

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var infuraKeyPattern = regexp.MustCompile(`(?:INFURA_API_KEY|infura_api_key|infura)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?`)

// Detector detects Infura API Keys.
type Detector struct{}

// ID returns the unique identifier of the Infura API Key detector.
func (d *Detector) ID() string { return "infura-api-key" }

// Description returns a human-readable description of the Infura API Key detector.
func (d *Detector) Description() string { return "Infura API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Infura API Key detection.
func (d *Detector) Keywords() []string {
	return []string{"INFURA_API_KEY", "infura_api_key", "infura"}
}

// Severity returns the default severity level for Infura API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Infura API Key patterns.
// The 32-character hex value is extracted from submatch group 1.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := infuraKeyPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		hexKey := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(hexKey),
			RawV2:      bytes.Clone(fullMatch),
			Redacted:   detector.RedactBytes(hexKey),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

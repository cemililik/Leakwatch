// Package linear provides a Linear API Key secret detector.
package linear

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var linearKeyPattern = regexp.MustCompile(`lin_api_[A-Za-z0-9]{40,}`)

// Detector detects Linear API Keys.
type Detector struct{}

// ID returns the unique identifier of the Linear API Key detector.
func (d *Detector) ID() string { return "linear-api-key" }

// Description returns a human-readable description of the Linear API Key detector.
func (d *Detector) Description() string { return "Linear API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Linear API Key detection.
func (d *Detector) Keywords() []string { return []string{"lin_api_"} }

// Severity returns the default severity level for Linear API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Linear API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := linearKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   "lin_api_****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

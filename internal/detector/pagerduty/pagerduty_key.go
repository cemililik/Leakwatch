// Package pagerduty provides a PagerDuty API Key secret detector.
package pagerduty

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Context-aware pattern: requires a PagerDuty-related keyword near the key value.
var pagerdutyKeyPattern = regexp.MustCompile(`(?:PAGERDUTY_API_KEY|pagerduty_api_key|pagerduty_token|PAGERDUTY_TOKEN|pagerduty)\s*[=:]\s*['"]?(u\+[A-Za-z0-9_-]{17,})['"]?`)

// contextKeywords are checked when the regex matches without context.
var contextKeywords = [][]byte{
	[]byte("pagerduty"),
	[]byte("PAGERDUTY"),
	[]byte("PagerDuty"),
}

// Detector detects PagerDuty API Keys.
type Detector struct{}

// ID returns the unique identifier of the PagerDuty API Key detector.
func (d *Detector) ID() string { return "pagerduty-api-key" }

// Description returns a human-readable description of the PagerDuty API Key detector.
func (d *Detector) Description() string { return "PagerDuty API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for PagerDuty API Key detection.
func (d *Detector) Keywords() []string { return []string{"pagerduty", "PAGERDUTY", "PagerDuty"} }

// Severity returns the default severity level for PagerDuty API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for PagerDuty API Key patterns.
// Requires a PagerDuty context keyword to avoid false positives from
// base64-encoded hashes (e.g., npm integrity checksums in package-lock.json).
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	// First check: does any PagerDuty keyword exist in the data?
	hasContext := false
	for _, kw := range contextKeywords {
		if bytes.Contains(data, kw) {
			hasContext = true
			break
		}
	}
	if !hasContext {
		return nil
	}

	matches := pagerdutyKeyPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := match[1]
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(value),
			Redacted:   "u+****" + string(value[len(value)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

// Package launchdarkly provides a LaunchDarkly SDK Key secret detector.
package launchdarkly

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var launchdarklyKeyPattern = regexp.MustCompile(`sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)

// Detector detects LaunchDarkly SDK Keys.
type Detector struct{}

// ID returns the unique identifier of the LaunchDarkly SDK Key detector.
func (d *Detector) ID() string { return "launchdarkly-sdk-key" }

// Description returns a human-readable description of the LaunchDarkly SDK Key detector.
func (d *Detector) Description() string { return "LaunchDarkly SDK Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for LaunchDarkly SDK Key detection.
func (d *Detector) Keywords() []string {
	return []string{"sdk-", "launchdarkly", "LAUNCHDARKLY"}
}

// Severity returns the default severity level for LaunchDarkly SDK Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for LaunchDarkly SDK Key patterns.
// The key is redacted to sdk-**** plus the last 4 characters.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := launchdarklyKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		redacted := "sdk-****" + s[len(s)-4:]

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

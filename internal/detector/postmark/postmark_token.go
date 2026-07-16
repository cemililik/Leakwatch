// Package postmark provides a Postmark Server API Token secret detector.
package postmark

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var postmarkTokenPattern = regexp.MustCompile(`(?:POSTMARK_SERVER_TOKEN|postmark_server_token|X-Postmark-Server-Token)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`)

// Detector detects Postmark Server API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Postmark token detector.
func (d *Detector) ID() string { return "postmark-server-token" }

// Description returns a human-readable description of the Postmark token detector.
func (d *Detector) Description() string { return "Postmark Server API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Postmark token detection.
func (d *Detector) Keywords() []string {
	return []string{"POSTMARK_SERVER_TOKEN", "postmark_server_token", "X-Postmark-Server-Token"}
}

// Severity returns the default severity level for Postmark token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Postmark Server API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := postmarkTokenPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match[1]),
			Redacted:   detector.RedactBytes(match[1]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

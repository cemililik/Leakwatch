// Package doppler provides a Doppler Service Token secret detector.
package doppler

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// dopplerTokenPattern matches every current Doppler token type: service
// tokens (st), personal tokens (pt), CLI/config tokens (ct) and SCIM tokens
// (scim). The token type is captured so the redacted output can reflect the
// actual prefix matched instead of a hardcoded one.
var dopplerTokenPattern = regexp.MustCompile(`dp\.(st|pt|ct|scim)\.[a-zA-Z0-9_-]{40,}`)

// Detector detects Doppler Service Tokens.
type Detector struct{}

// ID returns the unique identifier of the Doppler token detector.
func (d *Detector) ID() string { return "doppler-token" }

// Description returns a human-readable description of the Doppler token detector.
func (d *Detector) Description() string { return "Doppler Service Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Doppler token detection.
// "dp." is the common prefix shared by every token type the pattern matches.
func (d *Detector) Keywords() []string { return []string{"dp."} }

// Severity returns the default severity level for Doppler token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Doppler token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := dopplerTokenPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		match := groups[0]
		tokenType := string(groups[1])
		s := string(match)
		redacted := "dp." + tokenType + ".****" + s[len(s)-4:]

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

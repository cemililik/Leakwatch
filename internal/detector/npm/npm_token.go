// Package npm provides an NPM Access Token secret detector.
package npm

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var npmTokenPattern = regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)

// Detector detects NPM Access Tokens.
type Detector struct{}

func (d *Detector) ID() string { return "npm-token" }

func (d *Detector) Description() string { return "NPM Access Token" }

func (d *Detector) Keywords() []string { return []string{"npm_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for NPM Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := npmTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   "npm_****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

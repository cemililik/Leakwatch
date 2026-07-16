// Package newrelic provides a New Relic API Key secret detector.
package newrelic

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var newRelicKeyPattern = regexp.MustCompile(`NRAK-[A-Z0-9]{27}`)

// Detector detects New Relic API Keys.
type Detector struct{}

func (d *Detector) ID() string { return "newrelic-api-key" }

func (d *Detector) Description() string { return "New Relic API Key" }

func (d *Detector) Keywords() []string { return []string{"NRAK-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for New Relic API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := newRelicKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   "NRAK-****" + s[len(s)-4:],
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

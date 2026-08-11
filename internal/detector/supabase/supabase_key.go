// Package supabase provides a Supabase personal access token detector.
package supabase

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var supabaseKeyPattern = regexp.MustCompile(`\bsbp_[a-f0-9]{40}\b`)

// Detector detects legacy Supabase Management API personal access tokens. The
// stable detector ID predates this naming correction; sbp_ is not a project
// service-role key.
type Detector struct{}

func (d *Detector) ID() string { return "supabase-service-key" }

func (d *Detector) Description() string { return "Supabase Personal Access Token" }

func (d *Detector) Keywords() []string { return []string{"sbp_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Supabase personal access token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := supabaseKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

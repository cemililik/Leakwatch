// Package databricks provides a Databricks Personal Access Token secret detector.
package databricks

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var databricksTokenPattern = regexp.MustCompile(`dapi[a-f0-9]{32}(-[0-9])?`)

// databricksHostPattern captures a co-located Databricks workspace host URL.
// A workspace PAT authenticates against its own workspace host, so the verifier
// needs this host to make a live call; it is non-secret context attached to the
// finding's ExtraData.
var databricksHostPattern = regexp.MustCompile(`https://[A-Za-z0-9.-]+\.(?:cloud\.databricks\.com|azuredatabricks\.net|gcp\.databricks\.com)`)

// Detector detects Databricks Personal Access Tokens.
type Detector struct{}

// ID returns the unique identifier of the Databricks Token detector.
func (d *Detector) ID() string { return "databricks-token" }

// Description returns a human-readable description of the Databricks Token detector.
func (d *Detector) Description() string { return "Databricks Personal Access Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Databricks Token detection.
func (d *Detector) Keywords() []string { return []string{"dapi"} }

// Severity returns the default severity level for Databricks Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Databricks Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := databricksTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	// Capture a co-located workspace host (if any) so the verifier can target
	// the correct workspace REST API. This is non-secret context.
	var host string
	if h := databricksHostPattern.Find(data); h != nil {
		host = string(h)
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		last4 := s[len(s)-4:]
		f := detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "dapi****" + last4,
		}
		if host != "" {
			f.ExtraData = map[string]string{"host": host}
		}
		findings = append(findings, f)
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

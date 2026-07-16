// Package heroku provides a Heroku API Key secret detector.
package heroku

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// (?i) makes the key-name portion case-insensitive to catch mixed/Pascal
// casing (e.g. "Heroku_Api_Key="); the Aho-Corasick pre-filter is already
// case-insensitive (internal/matcher/matcher.go lowercases both keywords and
// data), so this closes a regex-stage-only gap.
var herokuKeyPattern = regexp.MustCompile(
	`(?i)(?:HEROKU_API_KEY|heroku_api_key|heroku)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`,
)

// Detector detects Heroku API Keys.
type Detector struct{}

func (d *Detector) ID() string          { return "heroku-api-key" }
func (d *Detector) Description() string { return "Heroku API Key" }

func (d *Detector) Keywords() []string {
	return []string{"HEROKU_API_KEY", "heroku_api_key", "heroku"}
}

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Heroku API Key patterns.
// It extracts the UUID from the first submatch group.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := herokuKeyPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, match := range allMatches {
		if len(match) < 2 {
			continue
		}
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match[1]),
			RawV2:      bytes.Clone(match[0]),
			Redacted:   detector.RedactBytes(match[1]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

// Package cloudflare provides a Cloudflare API Token secret detector.
package cloudflare

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	// Context-aware pattern: matches Cloudflare-related variable names followed by a 40-char token.
	cloudflareTokenPattern = regexp.MustCompile(`(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare_api_token|cf_api_key)\s*[=:]\s*['"]?([A-Za-z0-9_-]{40})['"]?`)

	// Context keywords used to confirm Cloudflare relevance in the data.
	contextKeywords = [][]byte{
		[]byte("cloudflare"),
		[]byte("CLOUDFLARE"),
		[]byte("CF_API_TOKEN"),
		[]byte("cf_api_token"),
		[]byte("cf_api_key"),
		[]byte("CLOUDFLARE_API_TOKEN"),
	}
)

// Detector detects Cloudflare API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Cloudflare API Token detector.
func (d *Detector) ID() string { return "cloudflare-api-token" }

// Description returns a human-readable description of the Cloudflare API Token detector.
func (d *Detector) Description() string { return "Cloudflare API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Cloudflare API Token detection.
// The matcher lowercases every keyword before indexing, so only one casing of
// each distinct keyword is needed here; case-variant duplicates are omitted.
func (d *Detector) Keywords() []string {
	return []string{"cloudflare", "cf_api_token", "cf_api_key"}
}

// Severity returns the default severity level for Cloudflare API Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Cloudflare API Token patterns.
// It requires a Cloudflare-related context keyword to be present in the data
// before attempting regex matching, reducing false positives.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	if !hasContextKeyword(data) {
		return nil
	}

	allMatches := cloudflareTokenPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		token := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(token),
			RawV2:      bytes.Clone(fullMatch),
			Redacted:   detector.RedactBytes(token),
		})
	}
	return findings
}

// hasContextKeyword checks whether the data contains a Cloudflare-related keyword.
func hasContextKeyword(data []byte) bool {
	for _, kw := range contextKeywords {
		if bytes.Contains(data, kw) {
			return true
		}
	}
	return false
}

func init() {
	detector.Register(&Detector{})
}

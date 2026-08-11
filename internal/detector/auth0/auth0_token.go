// Package auth0 provides an Auth0 Management API Token secret detector.
package auth0

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var auth0TokenPattern = regexp.MustCompile(`(?:["']?(?:AUTH0_MANAGEMENT_TOKEN|AUTH0_API_TOKEN|auth0_token)["']?)[ \t]*[=:][ \t]*["']?([A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,})`)

// Detector detects Auth0 Management API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Auth0 Management Token detector.
func (d *Detector) ID() string { return "auth0-management-token" }

// Description returns a human-readable description of the Auth0 Management Token detector.
func (d *Detector) Description() string { return "Auth0 Management API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Auth0 Management Token detection.
func (d *Detector) Keywords() []string {
	return []string{"AUTH0_MANAGEMENT_TOKEN", "AUTH0_API_TOKEN", "auth0_token", "auth0"}
}

// Severity returns the default severity level for Auth0 Management Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Auth0 Management API Token patterns.
// The token value is extracted from submatch group 1 and redacted to first 8 chars + ****.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := auth0TokenPattern.FindAllSubmatchIndex(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		if len(groups) < 4 || groups[2] < 0 || !auth0TokenBoundary(data, groups[3]) {
			continue
		}
		fullMatch := bytes.Clone(data[groups[0]:groups[1]])
		tokenValue := bytes.Clone(data[groups[2]:groups[3]])

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        tokenValue,
			RawV2:      fullMatch,
			Redacted:   detector.RedactBytes(tokenValue),
			ByteStart:  groups[2],
			ByteEnd:    groups[3],
		})
	}
	return findings
}

func auth0TokenBoundary(data []byte, end int) bool {
	if end >= len(data) {
		return true
	}
	next := data[end]
	return (next < 'A' || next > 'Z') && (next < 'a' || next > 'z') &&
		(next < '0' || next > '9') && next != '_' && next != '-' && next != '.'
}

func init() {
	detector.Register(&Detector{})
}

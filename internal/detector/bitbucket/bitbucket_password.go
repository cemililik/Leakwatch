// Package bitbucket provides a Bitbucket App Password secret detector.
package bitbucket

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// bitbucketPasswordPattern extracts the app password value. The bare word
// "bitbucket" is deliberately NOT accepted as a left-hand-side identifier here
// (it stays in Keywords() for Aho-Corasick pre-filtering only): accepting it
// caused broad false positives on lines like "bitbucket: <workspace-uuid>".
var bitbucketPasswordPattern = regexp.MustCompile(`(?:BITBUCKET_APP_PASSWORD|bitbucket_app_password|bitbucket_password)\s*[=:]\s*['"]?([A-Za-z0-9]{18,24})['"]?`)

// bitbucketUsernamePattern captures a co-located Bitbucket username so the
// verifier (which needs username + app-password Basic auth) can run. The
// captured username is non-secret context attached to the finding's ExtraData.
var bitbucketUsernamePattern = regexp.MustCompile(`(?i)(?:BITBUCKET_USERNAME|BITBUCKET_USER|ATLASSIAN_USERNAME|ATLASSIAN_USER)\s*[=:]\s*['"]?([A-Za-z0-9._-]+)['"]?`)

// Detector detects Bitbucket App Passwords.
type Detector struct{}

// ID returns the unique identifier of the Bitbucket App Password detector.
func (d *Detector) ID() string { return "bitbucket-app-password" }

// Description returns a human-readable description of the Bitbucket App Password detector.
func (d *Detector) Description() string { return "Bitbucket App Password" }

// Keywords returns the Aho-Corasick pre-filter keywords for Bitbucket App Password detection.
func (d *Detector) Keywords() []string {
	return []string{"BITBUCKET_APP_PASSWORD", "bitbucket_app_password", "bitbucket"}
}

// Severity returns the default severity level for Bitbucket App Password findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Bitbucket App Password patterns.
// The password value is extracted from submatch group 1.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := bitbucketPasswordPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	// Capture a co-located username (if any) so the verifier can perform the
	// Basic-auth call it requires. This is non-secret context.
	var username string
	if u := bitbucketUsernamePattern.FindSubmatch(data); u != nil {
		username = string(u[1])
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		password := groups[1]

		f := detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        password,
			RawV2:      fullMatch,
			Redacted:   detector.RedactBytes(password),
		}
		if username != "" {
			f.ExtraData = map[string]string{"username": username}
		}
		findings = append(findings, f)
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

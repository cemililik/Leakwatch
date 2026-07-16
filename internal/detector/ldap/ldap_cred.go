// Package ldap provides an LDAP/LDAPS Bind Credentials secret detector.
package ldap

import (
	"bytes"
	"context"
	"net/url"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// The scheme portion uses a scoped (?i:...) flag so it also matches uppercase
// or mixed-case schemes (e.g. "LDAP://"), which some tooling/generators and
// hand-edited configs emit; the Aho-Corasick pre-filter is already
// case-insensitive, so without this the regex stage silently missed those
// variants. Credentials themselves stay case-sensitive.
var ldapCredPattern = regexp.MustCompile(`(?i:ldaps?)://[^\s'"]+:[^\s'"]+@[^\s'"]+`)

// Detector detects LDAP/LDAPS Bind Credentials in connection URLs.
type Detector struct{}

// ID returns the unique identifier of the LDAP Credentials detector.
func (d *Detector) ID() string { return "ldap-credentials" }

// Description returns a human-readable description of the LDAP Credentials detector.
func (d *Detector) Description() string { return "LDAP/LDAPS Bind Credentials" }

// Keywords returns the Aho-Corasick pre-filter keywords for LDAP Credentials detection.
func (d *Detector) Keywords() []string {
	return []string{"ldap://", "ldaps://"}
}

// Severity returns the default severity level for LDAP Credentials findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for LDAP/LDAPS credential patterns.
// The password portion of the URL is redacted in the finding output.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := ldapCredPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redactPassword(string(match)),
		})
	}
	return findings
}

// redactPassword masks the password portion in an LDAP/LDAPS connection URL.
// Uses net/url.Parse for proper parsing, then reconstructs with masked password.
func redactPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "****"
	}
	if u.User == nil {
		return raw
	}
	username := u.User.Username()
	u.User = nil
	return u.Scheme + "://" + username + ":****@" + u.Host + u.RequestURI()
}

func init() {
	detector.Register(&Detector{})
}

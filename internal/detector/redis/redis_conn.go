// Package redis provides a Redis Connection String secret detector.
package redis

import (
	"context"
	"net/url"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var redisConnPattern = regexp.MustCompile(`rediss?://[^\s'"]+:[^\s'"]+@[^\s'"]+`)

// Detector detects Redis Connection Strings containing credentials.
type Detector struct{}

// ID returns the unique identifier of the Redis Connection String detector.
func (d *Detector) ID() string { return "redis-connection-string" }

// Description returns a human-readable description of the Redis Connection String detector.
func (d *Detector) Description() string { return "Redis Connection String" }

// Keywords returns the Aho-Corasick pre-filter keywords for Redis Connection String detection.
func (d *Detector) Keywords() []string {
	return []string{"redis://", "rediss://"}
}

// Severity returns the default severity level for Redis Connection String findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Redis Connection String patterns.
// The password portion of the URL is redacted in the finding output.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := redisConnPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redactPassword(string(match)),
		})
	}
	return findings
}

// redactPassword masks the password portion in a Redis connection URL.
// Uses net/url.Parse for proper parsing, then reconstructs with masked password.
//
// It is fail-safe: it NEVER returns the raw input. If the URL cannot be parsed,
// or net/url finds no userinfo component in the authority (in which case a
// credential may still be embedded elsewhere in the match, e.g. in the path or
// query, because the detector regex only excludes whitespace and quotes), the
// entire value is masked so no cleartext credential can escape.
func redactPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "****"
	}
	if u.User == nil {
		if u.Scheme == "" {
			return "****"
		}
		return u.Scheme + "://****"
	}
	username := u.User.Username()
	u.User = nil
	return u.Scheme + "://" + username + ":****@" + u.Host + u.RequestURI()
}

func init() {
	detector.Register(&Detector{})
}

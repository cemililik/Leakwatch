// Package jwt provides a detector for JSON Web Tokens.
package jwt

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

// ghsPrefix marks a GitHub stateless installation token (ghs_APPID_<jwt>). The
// embedded JWT also matches jwtPattern, but it is already reported in full by
// the github-oauth-token detector, so this detector suppresses it to avoid
// splitting one secret into two findings (see isGitHubStatelessBody).
var ghsPrefix = []byte("ghs_")

// JWT detects JSON Web Tokens.
type JWT struct{}

// ID returns the unique identifier of the JWT detector.
func (d *JWT) ID() string { return "jwt" }

// Description returns a human-readable description of the JWT detector.
func (d *JWT) Description() string { return "JSON Web Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for JWT detection.
func (d *JWT) Keywords() []string { return []string{"eyJ"} }

// Severity returns the default severity level for JWT findings.
func (d *JWT) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for JSON Web Token patterns.
func (d *JWT) Scan(_ context.Context, data []byte) []detector.RawFinding {
	locs := jwtPattern.FindAllIndex(data, -1)
	if len(locs) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(locs))
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		// Skip JWTs that are the body of a GitHub stateless installation token
		// (ghs_APPID_<jwt>); those are reported in full by github-oauth-token.
		if isGitHubStatelessBody(data, start) {
			continue
		}
		match := data[start:end]
		// Reveal only the trailing characters to avoid exposing the JWT
		// header, payload, or signature.
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   detector.RedactBytes(match),
		})
	}
	if len(findings) == 0 {
		return nil
	}
	return findings
}

// isGitHubStatelessBody reports whether the JWT beginning at start is the body
// of a GitHub stateless installation token (ghs_APPID_<jwt>). RE2 has no
// lookbehind, so it walks back over the contiguous token run (base64url plus the
// ghs_/app-ID separators) immediately preceding the match and checks whether
// that run contains the literal "ghs_".
//
// Contains rather than HasPrefix: the run may carry leading base64url bytes with
// no delimiter (e.g. "xghs_APPID_"). Wherever "ghs_" appears in the run, the run
// has no dots (dots are not token bytes) so it is glued straight onto this JWT,
// forming a "ghs_...eyJ.eyJ.sig" shape that the github-oauth-token detector
// captures in full — its per-segment floors ({8,}) are at or below this
// detector's ({10,}). Suppressing here therefore only removes a duplicate of a
// secret the github detector already reports; it can never drop one. (This
// assumes the github-oauth-token detector is active, which it is by default.)
func isGitHubStatelessBody(data []byte, start int) bool {
	i := start
	for i > 0 && isTokenByte(data[i-1]) {
		i--
	}
	return bytes.Contains(data[i:start], ghsPrefix)
}

// isTokenByte reports whether b is part of a contiguous token run: a base64url
// character or one of the separators ('_', '-') that appear in a ghs_ token.
func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '-':
		return true
	default:
		return false
	}
}

func init() {
	detector.Register(&JWT{})
}

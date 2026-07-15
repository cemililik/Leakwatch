package github

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// oauthTokenPattern matches GitHub server-/user-to-server tokens. There are two
// shapes to cover, so the pattern is an ordered alternation:
//
//  1. ghs_ STATELESS installation tokens (rolled out from April 2026). These are
//     ghs_APPID_<jwt> — a ghs_ prefix, the app ID, an underscore, then a JWT
//     (header.payload.signature). They are ~520 chars and contain exactly two
//     dots, so the legacy `[A-Za-z0-9_]` body class truncated them at the first
//     dot (or missed them when a base64url '-' appeared early). This branch
//     captures the whole token: a base64url run followed by exactly two
//     dot-separated base64url runs. It is listed FIRST so a stateless token is
//     never claimed by the shorter opaque branch below.
//  2. ghs_/gho_/ghu_/ghr_ OPAQUE tokens (legacy ghs_ and the still-opaque
//     gho_/ghu_/ghr_): a fixed prefix followed by >=36 of [A-Za-z0-9_].
//
// ghp_ Personal Access Tokens are deliberately excluded and handled by the
// github-token detector (see github_token.go), so any single token is reported
// by exactly one detector.
//
// Note on ghu_ (user-to-server): GitHub has signalled that ghu_ tokens will also
// move to the stateless JWT format later, but the format/timeline are not yet
// published. ghu_ is intentionally left opaque here; when GitHub documents the
// new ghu_ shape, add it to the stateless branch (gh[su]_...) rather than
// guessing at an unspecified format now.
//
// Branch 1 is `ghs_[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,}){2}` (stateless
// ghs_APPID_<jwt>); branch 2 is `gh[orus]_[A-Za-z0-9_]{36,}` (opaque
// gho_/ghu_/ghr_/legacy ghs_). The pattern is one raw-string literal — not
// concatenated fragments — so the tools/site-build detector extractor, which
// reads the MustCompile argument from the AST, can still pick it up.
var oauthTokenPattern = regexp.MustCompile(`ghs_[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,}){2}|gh[orus]_[A-Za-z0-9_]{36,}`)

// OAuthDetector detects GitHub server-/user-to-server tokens
// (gho_/ghu_/ghr_/ghs_), including new stateless ghs_ installation tokens.
type OAuthDetector struct{}

// ID returns the unique identifier of the GitHub OAuth2 token detector.
func (d *OAuthDetector) ID() string { return "github-oauth-token" }

// Description returns a human-readable description of the GitHub OAuth2 token detector.
func (d *OAuthDetector) Description() string { return "GitHub OAuth2 & Installation Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for GitHub OAuth2 token detection.
func (d *OAuthDetector) Keywords() []string { return []string{"gho_", "ghu_", "ghr_", "ghs_"} }

// Severity returns the default severity level for GitHub OAuth2 token findings.
func (d *OAuthDetector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for GitHub OAuth2 Token patterns.
func (d *OAuthDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := oauthTokenPattern.FindAll(data, -1)
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
	detector.Register(&OAuthDetector{})
}

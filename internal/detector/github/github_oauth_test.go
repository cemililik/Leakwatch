package github

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &OAuthDetector{}
	assert.Equal(t, "github-oauth-token", d.ID())
	assert.Equal(t, "GitHub OAuth2 & Installation Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestOAuthDetector_Scan_MatchAndReject(t *testing.T) {
	// Synthetic 40-char suffix (above 36 minimum)
	suffix40 := strings.Repeat("Abc1D678", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid gho_ token",
			input:    "gho_" + suffix40,
			expected: 1,
			redacted: "****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid ghr_ token",
			input:    "ghr_" + suffix40,
			expected: 1,
			redacted: "****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid ghu_ token",
			input:    "ghu_" + suffix40,
			expected: 1,
			redacted: "****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid ghs_ token",
			input:    "ghs_" + suffix40,
			expected: 1,
			redacted: "****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "token embedded in config",
			input:    `GITHUB_TOKEN=gho_` + suffix40,
			expected: 1,
		},
		{
			name:     "no match - suffix too short",
			input:    "gho_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix ghp",
			input:    "ghp_" + suffix40,
			expected: 0,
		},
		{
			name:     "no match - wrong prefix ghx",
			input:    "ghx_" + suffix40,
			expected: 0,
		},
		{
			name:     "no match - plain text",
			input:    "this is just normal text",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
	}

	d := &OAuthDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

// fakeStatelessToken builds an obviously-fake GitHub stateless installation
// token of the ghs_APPID_<jwt> form (header.payload.signature). It is assembled
// from parts at runtime so the source file never contains a contiguous,
// real-looking token literal that secret push-protection could flag.
func fakeStatelessToken(headerTail string) string {
	const appID = "12345678"
	header := "eyJ" + headerTail
	payload := "eyJ" + strings.Repeat("Gh1Ij2Kl", 30)
	signature := strings.Repeat("Mn3Op4Qr", 12)
	return "ghs_" + appID + "_" + header + "." + payload + "." + signature
}

// TestOAuthDetector_Scan_StatelessToken_CapturesWholeToken proves the new
// ghs_APPID_<jwt> stateless installation tokens are captured in full by a single
// github-oauth-token finding (the pre-2026 behaviour truncated them at the first
// dot or missed them entirely when a base64url '-' appeared early).
func TestOAuthDetector_Scan_StatelessToken_CapturesWholeToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "long alphanumeric header segment",
			token: fakeStatelessToken(strings.Repeat("Ab9Cd0Ef", 5)),
		},
		{
			name:  "base64url dash early in header",
			token: fakeStatelessToken("Ab-Cd0Ef9Gh"),
		},
		{
			name:  "base64url underscore in header",
			token: fakeStatelessToken("Ab_Cd0Ef9Gh_Ij"),
		},
		{
			name:  "short app id",
			token: "ghs_42_" + "eyJ" + strings.Repeat("Ab9Cd0Ef", 4) + "." + "eyJ" + strings.Repeat("Gh1Ij2Kl", 20) + "." + strings.Repeat("Mn3Op4Qr", 10),
		},
	}

	d := &OAuthDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.token))
			require.Len(t, findings, 1, "stateless token must yield exactly one finding")

			f := findings[0]
			assert.Equal(t, "github-oauth-token", f.DetectorID)
			// The whole token is captured, not just the header segment.
			assert.Equal(t, tt.token, string(f.Raw), "must capture the entire token")
			assert.Greater(t, len(f.Raw), 100, "stateless tokens are long")

			// Redaction stays safe for a long token: only the last four
			// characters are ever revealed.
			assert.Equal(t, "****"+tt.token[len(tt.token)-4:], f.Redacted)
			assert.Len(t, f.Redacted, len("****")+4)
			assert.NotContains(t, f.Redacted, tt.token[:len(tt.token)-4],
				"redaction must not expose the token body")
		})
	}
}

// TestOAuthDetector_Scan_NoOverCapture guards the greedy branches against eating
// surrounding context: opaque tokens must not start consuming dots, and a
// stateless token must stop at its third (signature) segment.
func TestOAuthDetector_Scan_NoOverCapture(t *testing.T) {
	suffix40 := strings.Repeat("Abc1D678", 5)
	stateless := fakeStatelessToken(strings.Repeat("Ab9Cd0Ef", 5))

	tests := []struct {
		name  string
		input string
		want  string // expected single captured match
	}{
		{
			name:  "opaque gho_ followed by dotted domain",
			input: "gho_" + suffix40 + ".example.com",
			want:  "gho_" + suffix40,
		},
		{
			name:  "stateless token at end of a sentence",
			input: "leaked token: " + stateless + ". Please rotate it.",
			want:  stateless,
		},
		{
			name:  "stateless token followed by a fourth dotted segment",
			input: stateless + "." + strings.Repeat("Qq11Ww22", 8),
			want:  stateless,
		},
	}

	d := &OAuthDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, 1)
			assert.Equal(t, tt.want, string(findings[0].Raw))
		})
	}
}

// TestOAuthDetector_Scan_LegacyOpaqueUnchanged confirms the legacy opaque shapes
// (including legacy opaque ghs_) are still captured whole and unchanged.
func TestOAuthDetector_Scan_LegacyOpaqueUnchanged(t *testing.T) {
	suffix40 := strings.Repeat("Abc1D678", 5)
	for _, prefix := range []string{"gho_", "ghu_", "ghr_", "ghs_"} {
		t.Run(prefix, func(t *testing.T) {
			token := prefix + suffix40
			findings := (&OAuthDetector{}).Scan(context.Background(), []byte(token))
			require.Len(t, findings, 1)
			assert.Equal(t, token, string(findings[0].Raw))
		})
	}
}

// TestGitHubDetectors_StatelessNoPrefixOverlap ensures a stateless ghs_ token is
// still claimed by exactly one of the two GitHub detectors (never the ghp_
// personal-access-token detector).
func TestGitHubDetectors_StatelessNoPrefixOverlap(t *testing.T) {
	token := []byte(fakeStatelessToken(strings.Repeat("Ab9Cd0Ef", 5)))

	tokenFindings := (&Token{}).Scan(context.Background(), token)
	oauthFindings := (&OAuthDetector{}).Scan(context.Background(), token)

	assert.Empty(t, tokenFindings, "ghp_ detector must not claim a ghs_ token")
	require.Len(t, oauthFindings, 1, "oauth detector must claim the ghs_ token")
}

// TestGitHubDetectors_NoPrefixOverlap_ReportedByExactlyOne is a regression test
// for the token/oauth prefix overlap (DETA-M-02): every GitHub token prefix must
// be claimed by exactly one of the two detectors, never both.
func TestGitHubDetectors_NoPrefixOverlap_ReportedByExactlyOne(t *testing.T) {
	suffix := strings.Repeat("Abc1D678", 5)

	tests := []struct {
		prefix         string
		wantTokenCount int
		wantOAuthCount int
	}{
		{prefix: "ghp_", wantTokenCount: 1, wantOAuthCount: 0},
		{prefix: "gho_", wantTokenCount: 0, wantOAuthCount: 1},
		{prefix: "ghu_", wantTokenCount: 0, wantOAuthCount: 1},
		{prefix: "ghs_", wantTokenCount: 0, wantOAuthCount: 1},
		{prefix: "ghr_", wantTokenCount: 0, wantOAuthCount: 1},
	}

	token := &Token{}
	oauth := &OAuthDetector{}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			input := []byte(tt.prefix + suffix)
			tokenFindings := token.Scan(context.Background(), input)
			oauthFindings := oauth.Scan(context.Background(), input)

			assert.Len(t, tokenFindings, tt.wantTokenCount, "token detector count")
			assert.Len(t, oauthFindings, tt.wantOAuthCount, "oauth detector count")
			// Exactly one detector must claim the token.
			assert.Equal(t, 1, len(tokenFindings)+len(oauthFindings),
				"prefix %q must be reported by exactly one detector", tt.prefix)
		})
	}
}

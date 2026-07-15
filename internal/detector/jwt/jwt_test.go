package jwt

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWT_Metadata(t *testing.T) {
	d := &JWT{}
	assert.Equal(t, "jwt", d.ID())
	assert.Equal(t, "JSON Web Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestJWT_Scan_MatchesValidTokens(t *testing.T) {
	// Fake JWT: header.payload.signature (all base64url-safe characters, no real secrets)
	fakeJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid JWT",
			input:    fakeJWT,
			expected: 1,
			redacted: "****WXYZ",
		},
		{
			name:     "JWT in authorization header",
			input:    "Authorization: Bearer " + fakeJWT,
			expected: 1,
		},
		{
			name:     "JWT in JSON",
			input:    `{"token": "` + fakeJWT + `"}`,
			expected: 1,
		},
		{
			name:     "multiple JWTs",
			input:    fakeJWT + " " + fakeJWT,
			expected: 2,
		},
		{
			name:     "JWT in large text",
			input:    strings.Repeat("a", 10000) + fakeJWT + strings.Repeat("b", 10000),
			expected: 1,
		},
	}

	d := &JWT{}
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

// TestJWT_Scan_SuppressesGitHubStatelessTokenBody verifies that the JWT body of
// a GitHub stateless installation token (ghs_APPID_<jwt>) is NOT reported by the
// jwt detector: that whole token is already reported by github-oauth-token, so
// emitting the embedded JWT too would split one secret into two findings.
func TestJWT_Scan_SuppressesGitHubStatelessTokenBody(t *testing.T) {
	// Built from parts so no contiguous real-looking token literal is committed.
	header := "eyJ" + strings.Repeat("Ab9Cd0Ef", 5)
	payload := "eyJ" + strings.Repeat("Gh1Ij2Kl", 30)
	signature := strings.Repeat("Mn3Op4Qr", 12)
	jwtBody := header + "." + payload + "." + signature
	statelessToken := "ghs_12345678_" + jwtBody

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "stateless ghs_ token body is suppressed",
			input:    statelessToken,
			expected: 0,
		},
		{
			name:     "stateless token embedded in config is suppressed",
			input:    "GITHUB_TOKEN=" + statelessToken + "\n",
			expected: 0,
		},
		{
			// A base64url char glued directly before "ghs_" (no delimiter) must
			// still be recognised as a ghs_ body: the github-oauth-token detector
			// matches "ghs_..." mid-string, so reporting the JWT too would double
			// the same secret.
			name:     "stateless token glued to a preceding token char is suppressed",
			input:    "x" + statelessToken,
			expected: 0,
		},
		{
			name:     "standalone JWT is still reported",
			input:    jwtBody,
			expected: 1,
		},
		{
			name:     "JWT preceded by a non-ghs token run is still reported",
			input:    "Bearer " + jwtBody,
			expected: 1,
		},
		{
			name:     "stateless token plus an unrelated standalone JWT",
			input:    statelessToken + " and also " + jwtBody,
			expected: 1,
		},
	}

	d := &JWT{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
		})
	}
}

func TestJWT_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "only header part",
			input: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			name:  "two parts only",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
		},
		{
			name:  "short signature",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.short",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &JWT{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

package auth0

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "auth0-management-token", d.ID())
	assert.Equal(t, "Auth0 Management API Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuZXUuYXV0aDAuY29tLyJ9.c2lnbmF0dXJlLWZpeHR1cmU"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		rawLen   int
	}{
		{
			name:     "AUTH0_MANAGEMENT_TOKEN with equals",
			input:    "AUTH0_MANAGEMENT_TOKEN=" + token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
		{
			name:     "AUTH0_API_TOKEN with equals",
			input:    "AUTH0_API_TOKEN=" + token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
		{
			name:     "auth0_token lowercase with equals",
			input:    "auth0_token=" + token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
		{
			name:     "AUTH0_MANAGEMENT_TOKEN with colon separator",
			input:    "AUTH0_MANAGEMENT_TOKEN: " + token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
		{
			name:     "AUTH0_API_TOKEN with single quotes",
			input:    "AUTH0_API_TOKEN='" + token + "'",
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
		{
			name:     "AUTH0_MANAGEMENT_TOKEN with double quotes",
			input:    `"AUTH0_MANAGEMENT_TOKEN": "` + token + `"`,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
		{
			name:     "token with spaces around equals",
			input:    "AUTH0_MANAGEMENT_TOKEN = " + token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
			rawLen:   len(token),
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
				assert.Len(t, findings[0].Raw, tt.rawLen)
				assert.Equal(t, token, string(findings[0].Raw))
				assert.Equal(t, token, tt.input[findings[0].ByteStart:findings[0].ByteEnd])
			}
		})
	}
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short token value",
			input: "AUTH0_MANAGEMENT_TOKEN=abc123",
		},
		{
			name:  "opaque value is not a management JWT",
			input: "AUTH0_MANAGEMENT_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp3VDIifQ",
		},
		{
			name:  "fourth JWT segment",
			input: "AUTH0_MANAGEMENT_TOKEN=aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccc.more",
		},
		{
			name:  "no recognized variable name",
			input: "API_TOKEN=aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.cccccccc",
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

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

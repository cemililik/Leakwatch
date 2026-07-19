package okta

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "okta-api-token", d.ID())
	assert.Equal(t, "Okta API Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 40-char suffix: total token = "00" + 40 chars = 42 chars
	suffix40 := strings.Repeat("Abc1Defg", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with okta context keyword",
			input:    "okta_token=00" + suffix40,
			expected: 1,
			redacted: "00****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid token with SSWS authorization header",
			input:    "Authorization: SSWS 00" + suffix40,
			expected: 1,
			redacted: "00****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid token with OKTA uppercase context",
			input:    "OKTA_API_TOKEN=00" + suffix40,
			expected: 1,
			redacted: "00****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "multiple tokens in same input with okta context",
			input:    "okta_token1=00" + suffix40 + "\nokta_token2=00" + strings.Repeat("Xyz9Abcd", 5),
			expected: 2,
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
				assert.Len(t, findings[0].Raw, 42)
			}
		})
	}
}

func TestDetector_Scan_CapturesOrgDomain(t *testing.T) {
	suffix40 := strings.Repeat("Abc1Defg", 5)
	token := "00" + suffix40

	tests := []struct {
		name       string
		input      string
		wantDomain string
	}{
		{
			name:       "domain in url with okta context",
			input:      "OKTA_URL=https://acme.okta.com\nokta_token=" + token,
			wantDomain: "acme.okta.com",
		},
		{
			name:       "oktapreview domain",
			input:      "issuer: https://dev-12345.oktapreview.com okta_token=" + token,
			wantDomain: "dev-12345.oktapreview.com",
		},
		{
			name:       "okta-emea domain without scheme",
			input:      "org=acme.okta-emea.com SSWS " + token,
			wantDomain: "acme.okta-emea.com",
		},
		{
			name:       "no domain co-located",
			input:      "okta_token=" + token,
			wantDomain: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, 1)
			if tt.wantDomain == "" {
				assert.Empty(t, findings[0].ExtraData["domain"])
				return
			}
			assert.Equal(t, tt.wantDomain, findings[0].ExtraData["domain"])
		})
	}
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	suffix40 := strings.Repeat("Abc1Defg", 5)

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "no context keyword present",
			input: "API_TOKEN=00" + suffix40,
		},
		{
			name:  "too short token with okta context",
			input: "okta_token=00abcdef",
		},
		{
			name:  "wrong prefix with okta context",
			input: "okta_token=XX" + suffix40,
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

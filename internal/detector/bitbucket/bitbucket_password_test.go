package bitbucket

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
	assert.Equal(t, "bitbucket-app-password", d.ID())
	assert.Equal(t, "Bitbucket App Password", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidPasswords(t *testing.T) {
	// Synthetic 20-char password
	password20 := strings.Repeat("AbCd", 5)
	// Synthetic 18-char password (minimum length)
	password18 := strings.Repeat("XyZ1", 4) + "Ab"
	// Synthetic 24-char password (maximum length)
	password24 := strings.Repeat("AbCd", 6)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		rawLen   int
	}{
		{
			name:     "BITBUCKET_APP_PASSWORD with equals",
			input:    "BITBUCKET_APP_PASSWORD=" + password20,
			expected: 1,
			redacted: "****" + password20[len(password20)-4:],
			rawLen:   20,
		},
		{
			name:     "bitbucket_app_password lowercase with equals",
			input:    "bitbucket_app_password=" + password20,
			expected: 1,
			redacted: "****" + password20[len(password20)-4:],
			rawLen:   20,
		},
		{
			name:     "bitbucket_password with colon separator",
			input:    "bitbucket_password: " + password20,
			expected: 1,
			redacted: "****" + password20[len(password20)-4:],
			rawLen:   20,
		},
		{
			name:     "BITBUCKET_APP_PASSWORD with single quotes",
			input:    "BITBUCKET_APP_PASSWORD='" + password20 + "'",
			expected: 1,
			redacted: "****" + password20[len(password20)-4:],
			rawLen:   20,
		},
		{
			name:     "BITBUCKET_APP_PASSWORD with double quotes",
			input:    `BITBUCKET_APP_PASSWORD="` + password20 + `"`,
			expected: 1,
			redacted: "****" + password20[len(password20)-4:],
			rawLen:   20,
		},
		{
			name:     "minimum length password 18 chars",
			input:    "BITBUCKET_APP_PASSWORD=" + password18,
			expected: 1,
			redacted: "****" + password18[len(password18)-4:],
			rawLen:   18,
		},
		{
			name:     "maximum length password 24 chars",
			input:    "BITBUCKET_APP_PASSWORD=" + password24,
			expected: 1,
			redacted: "****" + password24[len(password24)-4:],
			rawLen:   24,
		},
		{
			name:     "spaces around equals",
			input:    "BITBUCKET_APP_PASSWORD = " + password20,
			expected: 1,
			redacted: "****" + password20[len(password20)-4:],
			rawLen:   20,
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
			}
		})
	}
}

func TestDetector_Scan_CapturesCoLocatedUsername(t *testing.T) {
	password20 := strings.Repeat("AbCd", 5)

	tests := []struct {
		name         string
		input        string
		wantUsername string
	}{
		{
			name:         "BITBUCKET_USERNAME assignment",
			input:        "BITBUCKET_USERNAME=jdoe\nBITBUCKET_APP_PASSWORD=" + password20,
			wantUsername: "jdoe",
		},
		{
			name:         "atlassian_user assignment",
			input:        "atlassian_user: john.doe\nbitbucket_app_password: " + password20,
			wantUsername: "john.doe",
		},
		{
			name:         "no username present",
			input:        "BITBUCKET_APP_PASSWORD=" + password20,
			wantUsername: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, 1)
			if tt.wantUsername == "" {
				assert.Nil(t, findings[0].ExtraData)
				return
			}
			require.NotNil(t, findings[0].ExtraData)
			assert.Equal(t, tt.wantUsername, findings[0].ExtraData["username"])
		})
	}
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "password too short",
			input: "BITBUCKET_APP_PASSWORD=abc123",
		},
		{
			name:  "password with invalid chars",
			input: "BITBUCKET_APP_PASSWORD=abc!@#$%^&*()invalid",
		},
		{
			name:  "no recognized variable name",
			input: "MY_PASSWORD=" + strings.Repeat("a", 20),
		},
		{
			// Bare "bitbucket:" must NOT match — it caused broad false
			// positives on workspace UUIDs, repo slugs, and commit fragments.
			name:  "bare bitbucket prefix with non-secret identifier",
			input: "bitbucket: " + strings.Repeat("a", 20),
		},
		{
			name:  "special characters in password",
			input: "BITBUCKET_APP_PASSWORD=ab!@#$%^&*()_+12345",
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

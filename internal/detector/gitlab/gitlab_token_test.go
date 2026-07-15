package gitlab

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "gitlab-pat", d.ID())
	assert.Equal(t, "GitLab Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 20-char token body
	tokenBody := "abcDEF1234567890xyzW"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid GitLab PAT",
			input:    "glpat-" + tokenBody,
			expected: 1,
			redacted: "glpat-****xyzW",
		},
		{
			name:     "key in config file",
			input:    `GITLAB_TOKEN=glpat-` + tokenBody,
			expected: 1,
		},
		{
			name:     "valid GitLab PAT longer than 20 chars",
			input:    "glpat-" + tokenBody + "EXTRAlongersuffix",
			expected: 1,
		},
		{
			name:     "no match - too short",
			input:    "glpat-abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "ghpat-" + tokenBody,
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

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
				assert.NotContains(t, findings[0].Redacted, tokenBody)
			}
		})
	}
}

func TestDetector_Scan_RoutableTokenPrefixes(t *testing.T) {
	// 20-char synthetic body shared by every prefix.
	body := "abcDEF1234567890xyzW"

	tests := []struct {
		name     string
		prefix   string
		redacted string
	}{
		{name: "deploy token", prefix: "gldt-", redacted: "gldt-****xyzW"},
		{name: "runner token", prefix: "glrt-", redacted: "glrt-****xyzW"},
		{name: "ci build token", prefix: "glcbt-", redacted: "glcbt-****xyzW"},
		{name: "pipeline trigger token", prefix: "glptt-", redacted: "glptt-****xyzW"},
		{name: "oauth app secret", prefix: "gloas-", redacted: "gloas-****xyzW"},
		{name: "feed token", prefix: "glft-", redacted: "glft-****xyzW"},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.prefix+body))
			require.Len(t, findings, 1)
			assert.Equal(t, tt.redacted, findings[0].Redacted)
			assert.NotContains(t, findings[0].Redacted, body)
		})
	}
}

func TestDetector_Scan_CapturesSelfHostedHost(t *testing.T) {
	token := "glpat-abcDEF1234567890xyzW"

	tests := []struct {
		name     string
		input    string
		wantHost string
	}{
		{
			name:     "self-hosted instance url",
			input:    "CI_SERVER_URL=https://gitlab.example.com\n" + token,
			wantHost: "gitlab.example.com",
		},
		{
			name:     "self-hosted with port",
			input:    "remote https://gitlab.corp.internal:8443/group/proj.git " + token,
			wantHost: "gitlab.corp.internal:8443",
		},
		{
			name:     "gitlab.com url",
			input:    "https://gitlab.com/acme/repo " + token,
			wantHost: "gitlab.com",
		},
		{
			name:     "no url co-located",
			input:    token,
			wantHost: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, 1)
			if tt.wantHost == "" {
				assert.Empty(t, findings[0].ExtraData["host"])
				return
			}
			assert.Equal(t, tt.wantHost, findings[0].ExtraData["host"])
		})
	}
}

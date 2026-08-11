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
		{name: "runner authentication token", prefix: "glrtr-", redacted: "glrtr-****xyzW"},
		{name: "ci build token", prefix: "glcbt-", redacted: "glcbt-****xyzW"},
		{name: "pipeline trigger token", prefix: "glptt-", redacted: "glptt-****xyzW"},
		{name: "incoming mail token", prefix: "glimt-", redacted: "glimt-****xyzW"},
		{name: "agent token", prefix: "glagent-", redacted: "glagent-****xyzW"},
		{name: "workhorse token", prefix: "glwt-", redacted: "glwt-****xyzW"},
		{name: "service account token", prefix: "glsoat-", redacted: "glsoat-****xyzW"},
		{name: "feature flags client token", prefix: "glffct-", redacted: "glffct-****xyzW"},
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

func TestDetector_Scan_NeverTreatsRepositoryHostAsTrustedContext(t *testing.T) {
	token := "glpat-abcDEF1234567890xyzW"
	inputs := []string{
		"CI_SERVER_URL=https://gitlab.attacker.example\n" + token,
		"CI_SERVER_URL=http://127.0.0.1:8080/gitlab\n" + token,
		"CI_SERVER_URL=https://gitlab.corp.internal:8443\n" + token,
		"CI_SERVER_URL=https://gitlab.com\n" + token,
	}
	d := &Detector{}
	for _, input := range inputs {
		findings := d.Scan(context.Background(), []byte(input))
		require.Len(t, findings, 1)
		assert.Empty(t, findings[0].ExtraData)
	}
}

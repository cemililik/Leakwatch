package github

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken_Metadata(t *testing.T) {
	d := &Token{}
	assert.Equal(t, "github-token", d.ID())
	assert.Equal(t, "GitHub Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestToken_Scan_MatchesValidTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid ghp token",
			input:    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 1,
			redacted: "****ghij",
		},
		{
			// gho/ghu/ghs/ghr prefixes belong exclusively to the OAuth
			// detector now; the token detector must ignore them.
			name:     "ignores gho oauth token",
			input:    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "ignores ghu oauth token",
			input:    "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "ignores ghs oauth token",
			input:    "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "ignores ghr oauth token",
			input:    "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "token in config file",
			input:    `GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`,
			expected: 1,
		},
		{
			name:     "token in JSON",
			input:    `{"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}`,
			expected: 1,
		},
		{
			// Only the ghp_ token is a PAT; the ghs_ token is an OAuth token.
			name:     "multiple tokens only ghp counted",
			input:    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 1,
		},
		{
			name:     "token in large text",
			input:    strings.Repeat("x", 10000) + "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &Token{}
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

func TestToken_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short suffix",
			input: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
		},
		{
			name:  "wrong prefix",
			input: "ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		},
		{
			name:  "github_pat_ too short suffix",
			input: "github_pat_ABCDEFGHIJK",
		},
		{
			name:  "plain text",
			input: "this is just normal text without tokens",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &Token{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

// TestToken_Scan_MatchesFineGrainedPAT regression-tests coverage for
// GitHub's fine-grained personal access tokens (`github_pat_...`), the
// default/recommended PAT type since 2022 and previously entirely unmatched.
// See review section 03-detectors-d2.md HIGH finding "github_token.go:16".
func TestToken_Scan_MatchesFineGrainedPAT(t *testing.T) {
	// synthetic 22-char suffix (the documented minimum)
	suffix22 := "ABCDEFGHIJKLMNOPQRSTUV"
	// synthetic longer suffix, matching the ~82-char body GitHub actually issues
	suffixLong := strings.Repeat("Abc1Defg", 9) + "Xyz9"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "fine-grained PAT with minimum-length suffix",
			input:    "github_pat_" + suffix22,
			expected: 1,
			redacted: "****" + suffix22[len(suffix22)-4:],
		},
		{
			name:     "fine-grained PAT with realistic-length suffix",
			input:    "github_pat_" + suffixLong,
			expected: 1,
			redacted: "****" + suffixLong[len(suffixLong)-4:],
		},
		{
			name:     "fine-grained PAT embedded in config",
			input:    `GITHUB_TOKEN=github_pat_` + suffixLong,
			expected: 1,
		},
		{
			name:     "classic and fine-grained PATs both present are counted separately",
			input:    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\ngithub_pat_" + suffixLong,
			expected: 2,
		},
	}

	d := &Token{}
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

// TestToken_ScanViaMatcher_FineGrainedPAT_IsDetected is a
// testutil.ScanViaMatcher regression test proving a fine-grained PAT
// (github_pat_...) survives the real Aho-Corasick matcher gate, i.e. that
// Keywords() was correctly broadened alongside the regex. Mirrors the
// telegram DETB-M-01 precedent.
func TestToken_ScanViaMatcher_FineGrainedPAT_IsDetected(t *testing.T) {
	input := "github_pat_" + strings.Repeat("Abc1Defg", 9) + "Xyz9"

	d := &Token{}
	findings := testutil.ScanViaMatcher(d, []byte(input))

	require.Len(t, findings, 1, "fine-grained PAT must survive the matcher gate")
	assert.Equal(t, "github-token", findings[0].DetectorID)
}

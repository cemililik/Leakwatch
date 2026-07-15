package openai

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "openai-api-key", d.ID())
	assert.Equal(t, "OpenAI API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 50-char suffix
	suffix50 := strings.Repeat("Abc1", 12) + "Xy"
	// synthetic 85-char suffix (valid but longer)
	suffix85 := strings.Repeat("Abc1", 21) + "X"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 50 char suffix",
			input:    "sk-proj-" + suffix50,
			expected: 1,
			redacted: "****" + ("sk-proj-" + suffix50)[len("sk-proj-"+suffix50)-4:],
		},
		{
			name:     "valid key with longer suffix",
			input:    "sk-proj-" + suffix85,
			expected: 1,
			redacted: "****" + ("sk-proj-" + suffix85)[len("sk-proj-"+suffix85)-4:],
		},
		{
			name:     "key embedded in config",
			input:    `OPENAI_API_KEY=sk-proj-` + suffix50,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "sk-proj-abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "sk-live-" + suffix50,
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
				assert.NotContains(t, findings[0].Redacted, suffix50)
			}
		})
	}
}

// TestDetector_Scan_LegacyAndServiceAccountKeys regression-tests the
// previously-missing legacy (sk-<20+ alnum>) and service-account
// (sk-svcacct-<20+ alnum>) key formats. Before this fix, only sk-proj-
// project keys were detected — a leaked legacy key, still common in
// pre-2024 codebases, produced zero findings. See review section
// 04-detectors-d3.md HIGH finding "openai_key.go:12" and
// docs/05-ROADMAP.md "Broaden OpenAI key coverage".
func TestDetector_Scan_LegacyAndServiceAccountKeys(t *testing.T) {
	// synthetic 24-char legacy-style suffix (mixed case + digits, no dashes)
	legacySuffix := "T3stLegacyKeyFakeSuffix"
	// synthetic 24-char service-account-style suffix
	svcAcctSuffix := "T3stSvcAcctKeyFakeSfx01"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "legacy sk- key standalone",
			input:    "sk-" + legacySuffix,
			expected: 1,
			redacted: "****" + legacySuffix[len(legacySuffix)-4:],
		},
		{
			name:     "legacy sk- key in config",
			input:    "OPENAI_API_KEY=sk-" + legacySuffix,
			expected: 1,
		},
		{
			name:     "legacy key too short - no match",
			input:    "sk-tooshort123",
			expected: 0,
		},
		{
			name:     "service-account key standalone",
			input:    "sk-svcacct-" + svcAcctSuffix,
			expected: 1,
			redacted: "****" + svcAcctSuffix[len(svcAcctSuffix)-4:],
		},
		{
			name:     "service-account key in config",
			input:    "OPENAI_API_KEY=sk-svcacct-" + svcAcctSuffix,
			expected: 1,
		},
		{
			name:     "project key not double-counted as legacy",
			input:    "sk-proj-" + strings.Repeat("Abc1", 12) + "Xy",
			expected: 1,
		},
		{
			name: "legacy and project keys both present are counted separately",
			input: "sk-" + legacySuffix + "\n" +
				"sk-proj-" + strings.Repeat("Abc1", 12) + "Xy",
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
			}
		})
	}
}

// TestDetector_ScanViaMatcher_LegacyKey_IsDetected is a
// testutil.ScanViaMatcher regression test proving a legacy key (which carries
// none of the more specific "sk-proj-"/"sk-svcacct-" substrings) still
// survives the real Aho-Corasick matcher gate, i.e. that Keywords() was
// correctly broadened alongside the regex. Mirrors the telegram DETB-M-01
// precedent.
func TestDetector_ScanViaMatcher_LegacyKey_IsDetected(t *testing.T) {
	legacySuffix := "T3stLegacyKeyFakeSuffix"
	input := "sk-" + legacySuffix

	d := &Detector{}
	findings := testutil.ScanViaMatcher(d, []byte(input))

	require.Len(t, findings, 1, "legacy key must survive the matcher gate")
	assert.Equal(t, "openai-api-key", findings[0].DetectorID)
}

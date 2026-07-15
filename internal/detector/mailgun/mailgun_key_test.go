package mailgun

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
	assert.Equal(t, "mailgun-api-key", d.ID())
	assert.Equal(t, "Mailgun API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 32-char hex string
	hex32 := "abcdef0123456789abcdef0123456789"
	hex32alt := "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid mailgun key with mailgun context",
			input:    "mailgun: key-" + hex32,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid mailgun key in config",
			input:    "MAILGUN_API_KEY=key-" + hex32,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid mailgun key with quotes",
			input:    `mailgun_api_key="key-` + hex32 + `"`,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid mailgun key with MAILGUN uppercase context elsewhere in file",
			input:    "# MAILGUN config\nkey-" + hex32,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "multiple keys in same input with mailgun context",
			input:    "MAILGUN_KEY1=key-" + hex32 + "\nMAILGUN_KEY2=key-" + hex32alt,
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
				assert.Len(t, findings[0].Raw, 36) // "key-" + 32 hex chars
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
			name:  "too short hex after key- prefix",
			input: "mailgun_key=key-abcdef0123",
		},
		{
			name:  "uppercase hex rejected",
			input: "mailgun_key=key-" + strings.ToUpper(strings.Repeat("ab", 16)),
		},
		{
			name:  "wrong prefix",
			input: "mailgun_key=api-" + strings.Repeat("a", 32),
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

// TestDetector_Scan_NoMailgunContext_SkipsMatch is a false-positive
// regression test for the missing context gate on a Critical-severity, very
// generic pattern (key-<32 hex>). Without a "mailgun" context requirement,
// unrelated identifiers sharing the same shape (cache keys, checksums,
// feature-flag/resource IDs) would be reported as Critical Mailgun API keys.
// See review section 04-detectors-d3.md HIGH finding "mailgun_key.go:13".
func TestDetector_Scan_NoMailgunContext_SkipsMatch(t *testing.T) {
	hex32 := "abcdef0123456789abcdef0123456789"

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "cache key with no mailgun context",
			input: "cache_key=key-" + hex32,
		},
		{
			name:  "feature flag id with no mailgun context",
			input: "feature_flag_id: key-" + hex32,
		},
		{
			name:  "standalone key- shape with no context at all",
			input: "key-" + hex32,
		},
		{
			name:  "terraform resource id with no mailgun context",
			input: `resource_id = "key-` + hex32 + `"`,
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings, "key-<32 hex> shape without mailgun context must not be reported")
		})
	}
}

// TestDetector_ScanViaMatcher_KeywordRegexAlignment is a
// testutil.ScanViaMatcher regression test proving the detector's Keywords()
// actually let the Aho-Corasick matcher gate select it at runtime for a
// realistic positive match, mirroring the telegram DETB-M-01 precedent.
func TestDetector_ScanViaMatcher_KeywordRegexAlignment(t *testing.T) {
	hex32 := "abcdef0123456789abcdef0123456789"
	input := "MAILGUN_API_KEY=key-" + hex32

	d := &Detector{}
	findings := testutil.ScanViaMatcher(d, []byte(input))

	require.Len(t, findings, 1, "realistic mailgun key assignment must survive the matcher gate")
	assert.Equal(t, "mailgun-api-key", findings[0].DetectorID)
}

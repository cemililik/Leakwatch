package pagerduty

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
	assert.Equal(t, "pagerduty-api-key", d.ID())
	assert.Equal(t, "PagerDuty API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

// TestDetector_Scan_RawIsIndependentOfInputBuffer is a memory-hygiene
// regression test proving Raw is an independent copy (via bytes.Clone)
// rather than a subslice aliasing the scanned chunk buffer. Without
// cloning, mutating the caller's buffer after Scan returns would also
// mutate the reported finding, and the finding would keep the whole chunk
// buffer alive for the rest of the scan.
// See review section 04-detectors-d3.md MEDIUM finding on Raw aliasing.
func TestDetector_Scan_RawIsIndependentOfInputBuffer(t *testing.T) {
	suffix20 := strings.Repeat("AbcD1", 4)
	data := []byte("PAGERDUTY_API_KEY=u+" + suffix20)

	d := &Detector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawCopy := append([]byte(nil), findings[0].Raw...)

	for i := range data {
		data[i] = 'X'
	}

	assert.Equal(t, rawCopy, findings[0].Raw, "Raw must not alias the mutated input buffer")
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// Synthetic 20-char suffix (above 17 minimum)
	suffix20 := strings.Repeat("AbcD1", 4)
	validKey := "u+" + suffix20

	// Longer suffix (30 chars)
	suffix30 := strings.Repeat("AbcD12", 5)
	longerKey := "u+" + suffix30

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 20 char suffix",
			input:    "PAGERDUTY_API_KEY=" + validKey,
			expected: 1,
			redacted: "u+****" + validKey[len(validKey)-4:],
		},
		{
			name:     "valid key with longer suffix",
			input:    "pagerduty_token=" + longerKey,
			expected: 1,
			redacted: "u+****" + longerKey[len(longerKey)-4:],
		},
		{
			name:     "key embedded in config",
			input:    `PAGERDUTY_API_KEY=u+` + suffix20,
			expected: 1,
		},
		{
			name:     "no match - key without pagerduty context",
			input:    validKey,
			expected: 0,
		},
		{
			name:     "no match - npm hash that looks like key",
			input:    "sha512-u+" + suffix20 + "==",
			expected: 0,
		},
		{
			name:     "no match - suffix too short",
			input:    "pagerduty u+abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "v+" + suffix20,
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
			}
		})
	}
}

package newrelic

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
	assert.Equal(t, "newrelic-api-key", d.ID())
	assert.Equal(t, "New Relic API Key", d.Description())
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
	suffix27 := strings.Repeat("ABC", 9)
	data := []byte("NRAK-" + suffix27)

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
	// synthetic 27-char uppercase alphanumeric suffix
	suffix27 := strings.Repeat("ABC", 9)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with exact 27 char suffix",
			input:    "NRAK-" + suffix27,
			expected: 1,
			redacted: "NRAK-****" + suffix27[len(suffix27)-4:],
		},
		{
			name:     "key embedded in env var",
			input:    `NEW_RELIC_API_KEY=NRAK-` + suffix27,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "NRAK-ABCDEF",
			expected: 0,
		},
		{
			name:     "no match - lowercase chars",
			input:    "NRAK-abcdefghijklmnopqrstuvwxyza",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "NRAQ-" + suffix27,
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

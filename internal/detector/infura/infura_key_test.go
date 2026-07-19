package infura

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "infura-api-key", d.ID())
	assert.Equal(t, "Infura API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 32-char hex key
	hexKey32 := "abcdef0123456789abcdef0123456789"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "INFURA_API_KEY with equals",
			input:    "INFURA_API_KEY=" + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "infura_api_key lowercase with equals",
			input:    "infura_api_key=" + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "infura with colon separator",
			input:    "infura: " + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "INFURA_API_KEY with single quotes",
			input:    "INFURA_API_KEY='" + hexKey32 + "'",
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "INFURA_API_KEY with double quotes",
			input:    `INFURA_API_KEY="` + hexKey32 + `"`,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "spaces around equals",
			input:    "INFURA_API_KEY = " + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
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
				// Raw should contain only the 32-char hex key
				assert.Len(t, findings[0].Raw, 32)
			}
		})
	}
}

// TestDetector_Scan_RawIsIndependentOfInputBuffer is a memory-hygiene
// regression test proving Raw/RawV2 are independent copies (via
// bytes.Clone) rather than subslices aliasing the scanned chunk buffer.
// Without cloning, mutating the caller's buffer after Scan returns would
// also mutate the reported finding, and the finding would keep the whole
// chunk buffer alive for the rest of the scan.
// See review section 04-detectors-d3.md MEDIUM finding on Raw aliasing.
func TestDetector_Scan_RawIsIndependentOfInputBuffer(t *testing.T) {
	hexKey32 := "abcdef0123456789abcdef0123456789"
	data := []byte("INFURA_API_KEY=" + hexKey32)

	d := &Detector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawCopy := append([]byte(nil), findings[0].Raw...)
	rawV2Copy := append([]byte(nil), findings[0].RawV2...)

	// Mutate the original buffer after Scan returns.
	for i := range data {
		data[i] = 'X'
	}

	assert.Equal(t, rawCopy, findings[0].Raw, "Raw must not alias the mutated input buffer")
	assert.Equal(t, rawV2Copy, findings[0].RawV2, "RawV2 must not alias the mutated input buffer")
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "non-hex characters in key",
			input: "INFURA_API_KEY=ghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			name:  "too short hex value",
			input: "INFURA_API_KEY=abcdef0123456789",
		},
		{
			name:  "non-hex characters",
			input: "INFURA_API_KEY=ghijklmnopqrstuvwxyz012345678901",
		},
		{
			name:  "no recognized variable name",
			input: "API_KEY=abcdef0123456789abcdef0123456789",
		},
		{
			name:  "uppercase hex not matched",
			input: "INFURA_API_KEY=ABCDEF0123456789ABCDEF0123456789",
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

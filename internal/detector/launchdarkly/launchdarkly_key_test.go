package launchdarkly

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "launchdarkly-sdk-key", d.ID())
	assert.Equal(t, "LaunchDarkly SDK Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic SDK key in the expected format.
	sdkKey := "sdk-abcdef01-2345-6789-abcd-ef0123456789"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "standalone SDK key",
			input:    sdkKey,
			expected: 1,
			redacted: "sdk-****6789",
		},
		{
			name:     "SDK key in env var",
			input:    "LAUNCHDARKLY_SDK_KEY=" + sdkKey,
			expected: 1,
			redacted: "sdk-****6789",
		},
		{
			name:     "SDK key in JSON config",
			input:    `{"sdk_key": "` + sdkKey + `"}`,
			expected: 1,
			redacted: "sdk-****6789",
		},
		{
			name:     "SDK key in YAML config",
			input:    "launchdarkly:\n  sdk_key: " + sdkKey,
			expected: 1,
			redacted: "sdk-****6789",
		},
		{
			name:     "multiple SDK keys",
			input:    sdkKey + " sdk-11111111-2222-3333-4444-555555555555",
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

// TestDetector_Scan_RawIsIndependentOfInputBuffer is a memory-hygiene
// regression test proving Raw is an independent copy (via bytes.Clone)
// rather than a subslice aliasing the scanned chunk buffer. Without
// cloning, mutating the caller's buffer after Scan returns would also
// mutate the reported finding, and the finding would keep the whole chunk
// buffer alive for the rest of the scan.
// See review section 04-detectors-d3.md MEDIUM finding on Raw aliasing.
func TestDetector_Scan_RawIsIndependentOfInputBuffer(t *testing.T) {
	sdkKey := "sdk-abcdef01-2345-6789-abcd-ef0123456789"
	data := []byte(sdkKey)

	d := &Detector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawCopy := append([]byte(nil), findings[0].Raw...)

	for i := range data {
		data[i] = 'X'
	}

	assert.Equal(t, rawCopy, findings[0].Raw, "Raw must not alias the mutated input buffer")
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "sdk- prefix with wrong format",
			input: "sdk-notavalidkeyformat",
		},
		{
			name:  "uppercase hex not matched",
			input: "sdk-ABCDEF01-2345-6789-ABCD-EF0123456789",
		},
		{
			name:  "missing sdk- prefix",
			input: "abcdef01-2345-6789-abcd-ef0123456789",
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

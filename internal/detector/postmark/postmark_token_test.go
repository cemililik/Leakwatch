package postmark

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "postmark-server-token", d.ID())
	assert.Equal(t, "Postmark Server API Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "POSTMARK_SERVER_TOKEN with equals",
			input:    `POSTMARK_SERVER_TOKEN=abcdef01-2345-6789-abcd-ef0123456789`,
			expected: 1,
			redacted: "****6789",
		},
		{
			name:     "postmark_server_token with colon",
			input:    `postmark_server_token: abcdef01-2345-6789-abcd-ef0123456789`,
			expected: 1,
			redacted: "****6789",
		},
		{
			name:     "X-Postmark-Server-Token header",
			input:    `X-Postmark-Server-Token: abcdef01-2345-6789-abcd-ef0123456789`,
			expected: 1,
			redacted: "****6789",
		},
		{
			name:     "POSTMARK_SERVER_TOKEN with quotes",
			input:    `POSTMARK_SERVER_TOKEN="abcdef01-2345-6789-abcd-ef0123456789"`,
			expected: 1,
			redacted: "****6789",
		},
		{
			name:     "POSTMARK_SERVER_TOKEN with single quotes",
			input:    `POSTMARK_SERVER_TOKEN='abcdef01-2345-6789-abcd-ef0123456789'`,
			expected: 1,
			redacted: "****6789",
		},
		{
			name:     "token in export statement",
			input:    `export POSTMARK_SERVER_TOKEN=abcdef01-2345-6789-abcd-ef0123456789`,
			expected: 1,
		},
		{
			name:     "multiple tokens",
			input:    "POSTMARK_SERVER_TOKEN=abcdef01-2345-6789-abcd-ef0123456789\nX-Postmark-Server-Token: 12345678-abcd-ef01-2345-6789abcdef01",
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
	data := []byte(`POSTMARK_SERVER_TOKEN=abcdef01-2345-6789-abcd-ef0123456789`)

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
			name:  "wrong variable name",
			input: "MY_TOKEN=abcdef01-2345-6789-abcd-ef0123456789",
		},
		{
			name:  "invalid UUID format",
			input: "POSTMARK_SERVER_TOKEN=notavaliduuid",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "UUID without variable prefix",
			input: "abcdef01-2345-6789-abcd-ef0123456789",
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

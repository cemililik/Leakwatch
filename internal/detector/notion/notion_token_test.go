package notion

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
	assert.Equal(t, "notion-token", d.ID())
	assert.Equal(t, "Notion Internal Integration Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 43-char alphanumeric suffix
	suffix43 := strings.Repeat("Ab1Cd2Ef3", 4) + "Gh1Ij2K"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "ntn_ prefix token standalone",
			input:    "ntn_" + suffix43,
			expected: 1,
			redacted: "****" + suffix43[len(suffix43)-4:],
		},
		{
			name:     "ntn_ prefix token in config",
			input:    "NOTION_TOKEN=ntn_" + suffix43,
			expected: 1,
			redacted: "****" + suffix43[len(suffix43)-4:],
		},
		{
			name:     "secret_ prefix with notion context",
			input:    "# Notion integration\nNOTION_TOKEN=secret_" + suffix43,
			expected: 1,
			redacted: "****" + suffix43[len(suffix43)-4:],
		},
		{
			name:     "ntn_ prefix with longer suffix",
			input:    "ntn_" + suffix43 + "ExtraChars123",
			expected: 1,
			redacted: "****" + "s123",
		},
		{
			name:     "multiple ntn_ tokens",
			input:    "ntn_" + suffix43 + " and ntn_" + strings.Repeat("Xy9Zw8Ab", 5) + "Cde",
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

func TestDetector_Scan_Raw_DoesNotAliasInputBuffer(t *testing.T) {
	suffix43 := strings.Repeat("Ab1Cd2Ef3", 4) + "Gh1Ij2K"
	input := []byte("ntn_" + suffix43)

	d := &Detector{}
	findings := d.Scan(context.Background(), input)
	require.Len(t, findings, 1)

	raw := findings[0].Raw
	original := string(raw)

	for i := range input {
		input[i] = 'x'
	}

	assert.Equal(t, original, string(raw))
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	suffix43 := strings.Repeat("Ab1Cd2Ef3", 4) + "Gh1Ij2K"

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "secret_ prefix without notion context",
			input: "API_SECRET=secret_" + suffix43,
		},
		{
			name:  "ntn_ prefix with too short suffix",
			input: "ntn_abc123",
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

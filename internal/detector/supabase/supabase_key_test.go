package supabase

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
	assert.Equal(t, "supabase-service-key", d.ID())
	assert.Equal(t, "Supabase Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 40-char hex suffix
	suffix40 := strings.Repeat("ab12cd34ef", 4)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 40 char hex suffix",
			input:    "sbp_" + suffix40,
			expected: 1,
			redacted: "****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "key embedded in env var",
			input:    `SUPABASE_ACCESS_TOKEN=sbp_` + suffix40,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "sbp_ab12cd34",
			expected: 0,
		},
		{
			name:     "no match - uppercase hex",
			input:    "sbp_" + strings.Repeat("AB12CD34EF", 4),
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "sbq_" + suffix40,
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

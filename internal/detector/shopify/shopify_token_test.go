package shopify

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
	assert.Equal(t, "shopify-access-token", d.ID())
	assert.Equal(t, "Shopify Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
	assert.True(t, d.AuthoritativeOnOverlap())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 32-char hex suffix
	suffix32 := strings.Repeat("ab12cd34", 4)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 32 char hex suffix",
			input:    "shpat_" + suffix32,
			expected: 1,
			redacted: "shpat_****" + suffix32[len(suffix32)-4:],
		},
		{
			name:     "token embedded in config",
			input:    `SHOPIFY_ACCESS_TOKEN=shpat_` + suffix32,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "shpat_ab12cd",
			expected: 0,
		},
		{
			name:     "no match - uppercase hex",
			input:    "shpat_" + strings.Repeat("AB12CD34", 4),
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "shpas_" + suffix32,
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

package shopify

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
	assert.Equal(t, "shopify-access-token", d.ID())
	assert.Equal(t, "Shopify Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
	assert.True(t, d.AuthoritativeOnOverlap())
}

func TestDetector_ScanViaMatcher_MatchesExactToken(t *testing.T) {
	suffix32 := strings.Repeat("ab12cd34", 4)
	findings := testutil.ScanViaMatcher(&Detector{}, []byte("SHOPIFY_ACCESS_TOKEN=shpat_"+suffix32))

	require.Len(t, findings, 1)
	assert.Equal(t, []byte("shpat_"+suffix32), findings[0].Raw)
	assert.Equal(t, strings.Index("SHOPIFY_ACCESS_TOKEN=shpat_"+suffix32, "shpat_"), findings[0].ByteStart)
	assert.Equal(t, string(findings[0].Raw), ("SHOPIFY_ACCESS_TOKEN=shpat_" + suffix32)[findings[0].ByteStart:findings[0].ByteEnd])
}

func TestDetector_Scan_ExactSpanSelectsAcceptedOccurrence(t *testing.T) {
	token := "shpat_" + strings.Repeat("ab12cd34", 4)
	input := "prefix_" + token + " # rejected duplicate\nSHOPIFY_ACCESS_TOKEN=" + token

	findings := (&Detector{}).Scan(context.Background(), []byte(input))
	require.Len(t, findings, 1)
	assert.Equal(t, strings.LastIndex(input, token), findings[0].ByteStart)
	assert.Equal(t, token, input[findings[0].ByteStart:findings[0].ByteEnd])
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
			name:     "no match - longer candidate",
			input:    "shpat_" + suffix32 + "a",
			expected: 0,
		},
		{
			name:     "no match - embedded in identifier",
			input:    "prefix_shpat_" + suffix32,
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

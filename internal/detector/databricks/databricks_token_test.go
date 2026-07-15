package databricks

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
	assert.Equal(t, "databricks-token", d.ID())
	assert.Equal(t, "Databricks Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 32-char hex string
	hex32 := strings.Repeat("abcdef01", 4)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token without version suffix",
			input:    "dapi" + hex32,
			expected: 1,
			redacted: "dapi****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid token with version suffix",
			input:    "dapi" + hex32 + "-2",
			expected: 1,
			redacted: "dapi****" + (hex32 + "-2")[len(hex32+"-2")-4:],
		},
		{
			name:     "token embedded in env var",
			input:    "DATABRICKS_TOKEN=dapi" + hex32,
			expected: 1,
			redacted: "dapi****" + hex32[len(hex32)-4:],
		},
		{
			name:     "token in config file",
			input:    `token = "dapi` + hex32 + `"`,
			expected: 1,
			redacted: "dapi****" + hex32[len(hex32)-4:],
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

func TestDetector_Scan_CapturesCoLocatedHost(t *testing.T) {
	hex32 := strings.Repeat("abcdef01", 4)

	tests := []struct {
		name     string
		input    string
		wantHost string
	}{
		{
			name:     "cloud.databricks.com host",
			input:    "DATABRICKS_HOST=https://dbc-a1b2345c-d6e7.cloud.databricks.com\nDATABRICKS_TOKEN=dapi" + hex32,
			wantHost: "https://dbc-a1b2345c-d6e7.cloud.databricks.com",
		},
		{
			name:     "azuredatabricks.net host",
			input:    "host = \"https://adb-123456789.10.azuredatabricks.net\"\ntoken = \"dapi" + hex32 + "\"",
			wantHost: "https://adb-123456789.10.azuredatabricks.net",
		},
		{
			name:     "no host present",
			input:    "DATABRICKS_TOKEN=dapi" + hex32,
			wantHost: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, 1)
			if tt.wantHost == "" {
				assert.Nil(t, findings[0].ExtraData)
				return
			}
			require.NotNil(t, findings[0].ExtraData)
			assert.Equal(t, tt.wantHost, findings[0].ExtraData["host"])
		})
	}
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short hex after dapi",
			input: "dapi" + strings.Repeat("ab", 8),
		},
		{
			name:  "wrong prefix",
			input: "xapi" + strings.Repeat("ab", 16),
		},
		{
			name:  "non-hex characters after dapi",
			input: "dapi" + strings.Repeat("zz", 16),
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

package pypi

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
	assert.Equal(t, "pypi-api-token", d.ID())
	assert.Equal(t, "PyPI API Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// macaroonPrefix is the fixed base64url macaroon-version header every real
	// PyPI token carries; the detector anchors on it to cut false positives.
	const macaroonPrefix = "pypi-AgEIcHlwaS5vcmc"
	// synthetic 50-char body (minimum accepted length)
	body50 := strings.Repeat("Abcd", 12) + "Ab"
	// synthetic 80-char body (longer valid token)
	body80 := strings.Repeat("Abcd", 20)
	// synthetic 16-char suffix used for the generic-shape false-positive cases
	suffix16 := strings.Repeat("Abcd", 4)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with minimum-length body",
			input:    macaroonPrefix + body50,
			expected: 1,
			redacted: "pypi-****" + body50[len(body50)-4:],
		},
		{
			name:     "valid token with longer body",
			input:    macaroonPrefix + body80,
			expected: 1,
			redacted: "pypi-****" + body80[len(body80)-4:],
		},
		{
			name:     "token embedded in config",
			input:    `PYPI_TOKEN=` + macaroonPrefix + body50,
			expected: 1,
		},
		{
			name:     "no match - too short body after macaroon prefix",
			input:    macaroonPrefix + "abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "npm_" + suffix16,
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
		{
			name:     "no match - generic pypi- string without the macaroon prefix (false-positive regression)",
			input:    "pypi-" + strings.Repeat(suffix16, 4), // 64 chars, well past the old 16-char floor
			expected: 0,
		},
		{
			name:     "no match - pypi- shaped Docker image tag",
			input:    "pypi-mirror-" + suffix16 + "-build",
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

// TestDetector_Scan_RawIsClonedNotAliased verifies Raw does not alias the
// scanned chunk buffer (memory/aliasing hardening).
func TestDetector_Scan_RawIsClonedNotAliased(t *testing.T) {
	const macaroonPrefix = "pypi-AgEIcHlwaS5vcmc"
	body := strings.Repeat("Abcd", 12) + "Ab"
	data := []byte(macaroonPrefix + body)

	d := &Detector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawBefore := string(findings[0].Raw)
	for i := range data {
		data[i] = 'x'
	}
	assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
}

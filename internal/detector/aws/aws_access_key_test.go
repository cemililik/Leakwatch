package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic, non-functional test fixtures. None of these are real credentials.
const (
	synthAKIA   = "AKIA1234567890ABCDEF"
	synthASIA   = "ASIA1234567890ABCDEF"
	synthSecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCD" // 40 chars, [A-Za-z0-9]
)

func TestAccessKeyID_Metadata(t *testing.T) {
	d := &AccessKeyID{}
	assert.Equal(t, "aws-access-key-id", d.ID())
	assert.Equal(t, "AWS Access Key ID", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestAccessKeyID_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid AKIA key",
			input:    synthAKIA,
			expected: 1,
			redacted: "****CDEF",
		},
		{
			name:     "valid ASIA key (temporary credentials)",
			input:    synthASIA,
			expected: 1,
			redacted: "****CDEF",
		},
		{
			name:     "key in config file",
			input:    "aws_access_key_id = " + synthAKIA,
			expected: 1,
		},
		{
			name:     "key in JSON",
			input:    `{"AccessKeyId": "` + synthAKIA + `"}`,
			expected: 1,
		},
		{
			name:     "no match - too short",
			input:    "AKIA1234567890",
			expected: 0,
		},
		{
			name:     "no match - plain text",
			input:    "this is just normal text",
			expected: 0,
		},
		{
			name:     "no match - lowercase",
			input:    "akia1234567890abcdef",
			expected: 0,
		},
		{
			name:     "multiple keys in text",
			input:    "key1: " + synthAKIA + " key2: " + synthASIA,
			expected: 2,
		},
		{
			name:     "key in large text",
			input:    strings.Repeat("\n", 10000) + synthAKIA + strings.Repeat("\n", 10000),
			expected: 1,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name:     "no match - AWS canonical documentation example key",
			input:    "AKIAIOSFODNN7EXAMPLE",
			expected: 0,
		},
		{
			name:     "no match - ASIA documentation example key",
			input:    "ASIAIOSFODNN7EXAMPLE",
			expected: 0,
		},
		{
			name:     "no match - truncated capture inside longer token (trailing)",
			input:    synthAKIA + "GHIJKLMNOP",
			expected: 0,
		},
		{
			name:     "no match - truncated capture inside longer token (leading)",
			input:    "ZZZ" + synthAKIA,
			expected: 0,
		},
	}

	d := &AccessKeyID{}
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

// TestAccessKeyID_Scan_PairsCoLocatedSecret verifies that a co-located Secret
// Access Key is captured into RawV2 (never ExtraData, never Redacted output) so
// the verifier can run, while remaining absent from any serialized surface.
func TestAccessKeyID_Scan_PairsCoLocatedSecret(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantRawV2  string
		wantPaired bool
	}{
		{
			name: "keyed secret assignment",
			input: "aws_access_key_id = " + synthAKIA + "\n" +
				"aws_secret_access_key = " + synthSecret,
			wantRawV2:  synthSecret,
			wantPaired: true,
		},
		{
			name:       "bare co-located secret within window",
			input:      synthAKIA + "\n" + synthSecret + "\n",
			wantRawV2:  synthSecret,
			wantPaired: true,
		},
		{
			name:       "no secret co-located",
			input:      synthAKIA,
			wantPaired: false,
		},
		{
			name:       "secret too far away (outside window)",
			input:      synthAKIA + strings.Repeat(" ", secretPairingRadius+50) + synthSecret,
			wantPaired: false,
		},
	}

	d := &AccessKeyID{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, 1)
			f := findings[0]

			if tt.wantPaired {
				require.NotNil(t, f.RawV2)
				assert.Equal(t, tt.wantRawV2, string(f.RawV2))
			} else {
				assert.Nil(t, f.RawV2)
			}

			// The secret must never leak into serialized surfaces.
			assert.NotContains(t, f.Redacted, synthSecret)
			for k, v := range f.ExtraData {
				assert.NotContains(t, v, synthSecret, "secret leaked into ExtraData[%q]", k)
			}
		})
	}
}

// TestScan_SecretPairing_DoesNotCarveSecretFromLongerToken guards the window
// anchoring bug: awsSecretBarePattern's ^/$ alternatives anchor to the sliced
// pairing window rather than to the full buffer, so a window edge landing
// inside a longer base64-like token could satisfy ^ and carve a spurious
// 40-character "Secret Access Key" out of the middle of that token.
//
// Layout is exact: a 140-char opaque token at offset 0, non-token padding, then
// the Access Key ID at offset 612. The pairing window therefore starts at
// 612-512=100, leaving exactly 40 token bytes (100..140) before a space — the
// one shape that satisfies the window-anchored ^...[^class] match. In the full
// buffer those 40 bytes are preceded by a token byte, so they are a slice of a
// longer token, not a standalone secret, and must not be paired.
func TestScan_SecretPairing_DoesNotCarveSecretFromLongerToken(t *testing.T) {
	longToken := strings.Repeat("ab12CD34", 17) + "wxyz" // exactly 140 chars
	require.Len(t, longToken, 140)
	data := []byte(longToken + strings.Repeat(" ", 472) + "AKIAQYRTZ4XN2WV6H8LM")

	findings := (&AccessKeyID{}).Scan(context.Background(), data)
	require.Len(t, findings, 1, "the access key ID itself must still be detected")
	assert.Nil(t, findings[0].RawV2,
		"a 40-char slice carved out of a longer token must not be paired as a secret key")
}

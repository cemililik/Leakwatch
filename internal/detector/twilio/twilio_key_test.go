package twilio

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
	assert.Equal(t, "twilio-api-key", d.ID())
	assert.Equal(t, "Twilio API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	// The SK API-Key SID pattern is self-contained, so the detector declares no
	// keywords and runs on every chunk (see Keywords doc comment).
	assert.Empty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 32-char hex string
	hex32 := "abcdef0123456789abcdef0123456789"
	hex32alt := "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		extraSID string
	}{
		{
			name:     "valid SK key with twilio context",
			input:    "twilio_api_key=SK" + hex32,
			expected: 1,
			redacted: "SK****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid SK key with Account SID in same data",
			input:    "TWILIO_ACCOUNT_SID=AC" + hex32alt + "\nTWILIO_API_KEY=SK" + hex32,
			expected: 1,
			redacted: "SK****" + hex32[len(hex32)-4:],
			extraSID: "AC" + hex32alt,
		},
		{
			name:     "multiple SK keys in same input",
			input:    "twilio_key1=SK" + hex32 + "\ntwilio_key2=SK" + hex32alt,
			expected: 2,
		},
		{
			name:     "SK key embedded in config line",
			input:    `TWILIO_API_KEY="SK` + hex32 + `"`,
			expected: 1,
			redacted: "SK****" + hex32[len(hex32)-4:],
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
				assert.Len(t, findings[0].Raw, 34) // "SK" + 32 hex chars
			}
			if tt.extraSID != "" {
				require.NotEmpty(t, findings)
				require.NotNil(t, findings[0].ExtraData)
				assert.Equal(t, tt.extraSID, findings[0].ExtraData["account_sid"])
			}
		})
	}
}

// TestDetector_ScanViaMatcher_StandaloneKey_IsDetected is a regression test for
// the keyword/regex misalignment (DETB-M-01). A standalone SK API-Key SID
// carries none of the words "twilio", so it must not be gated out by the
// Aho-Corasick matcher before Scan runs.
func TestDetector_ScanViaMatcher_StandaloneKey_IsDetected(t *testing.T) {
	hex32 := "abcdef0123456789abcdef0123456789"
	key := "SK" + hex32

	d := &Detector{}
	findings := testutil.ScanViaMatcher(d, []byte(key))

	require.Len(t, findings, 1, "standalone SK key must survive the matcher gate")
	assert.Equal(t, "twilio-api-key", findings[0].DetectorID)
	assert.Equal(t, "SK****"+hex32[len(hex32)-4:], findings[0].Redacted)
}

// TestDetector_Scan_ScopesAccountSIDToNearestKey verifies that when two
// unrelated key/SID pairs appear in the same chunk, each key is attributed the
// SID nearest to it rather than the first SID in the chunk.
func TestDetector_Scan_ScopesAccountSIDToNearestKey(t *testing.T) {
	hexA := "aaaaaaaa11111111aaaaaaaa11111111"
	hexB := "bbbbbbbb22222222bbbbbbbb22222222"
	sidA := "AC" + hexA
	sidB := "AC" + hexB
	keyA := "SK" + hexA
	keyB := "SK" + hexB

	// Two well-separated credential blocks: block A then, far away, block B.
	input := sidA + " " + keyA + strings.Repeat(" ", 600) + sidB + " " + keyB

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(input))

	require.Len(t, findings, 2)
	require.NotNil(t, findings[0].ExtraData)
	require.NotNil(t, findings[1].ExtraData)
	assert.Equal(t, sidA, findings[0].ExtraData["account_sid"])
	assert.Equal(t, sidB, findings[1].ExtraData["account_sid"])
}

// TestDetector_Scan_FarAwaySID_NotAttributed verifies that an Account SID
// beyond the proximity window is not attached to a key.
func TestDetector_Scan_FarAwaySID_NotAttributed(t *testing.T) {
	hex32 := "abcdef0123456789abcdef0123456789"
	// SID sits well beyond sidProximityWindow (512) bytes from the key.
	input := "AC" + strings.Repeat("a", 32) + strings.Repeat(" ", 700) + "SK" + hex32

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(input))

	require.Len(t, findings, 1)
	assert.Nil(t, findings[0].ExtraData)
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong prefix with twilio context",
			input: "twilio_key=AB" + strings.Repeat("a", 32),
		},
		{
			name:  "too short hex with twilio context",
			input: "twilio_key=SKabcdef0123",
		},
		{
			name:  "uppercase hex rejected",
			input: "twilio_key=SK" + strings.ToUpper(strings.Repeat("ab", 16)),
		},
		{
			name:  "Account SID alone is not a finding",
			input: "twilio_sid=AC" + strings.Repeat("a", 32),
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

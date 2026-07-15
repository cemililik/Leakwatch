package privatekey

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "private-key", d.ID())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "RSA private key",
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "OpenSSH private key",
			input:    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n-----END OPENSSH PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "EC private key",
			input:    "-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "DSA private key",
			input:    "-----BEGIN DSA PRIVATE KEY-----\nMIIB...\n-----END DSA PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "generic private key (PKCS8)",
			input:    "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "encrypted private key (PKCS8)",
			input:    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF...\n-----END ENCRYPTED PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "PGP private key block",
			input:    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxcLY...",
			expected: 1,
		},
		{
			name:     "public key - no match",
			input:    "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
			expected: 0,
		},
		{
			name:     "certificate - no match",
			input:    "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----",
			expected: 0,
		},
		{
			name:     "plain text - no match",
			input:    "just some normal text",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name:     "multiple keys",
			input:    "-----BEGIN RSA PRIVATE KEY-----\n...\n-----BEGIN EC PRIVATE KEY-----",
			expected: 2,
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
		})
	}
}

// TestDetector_Scan_CapturesBlockRegionWithoutLeakingBody verifies DETB-M-02:
// the detector measures the full BEGIN..END block region but never stores the
// key body in Raw, RawV2, or Redacted. The body below is clearly fake.
func TestDetector_Scan_CapturesBlockRegionWithoutLeakingBody(t *testing.T) {
	body := "FAKEBODYLINE1FAKEBODYLINE2FAKEBODYLINE3"
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(pem))

	assert.Len(t, findings, 1)
	f := findings[0]

	// The PEM body must never appear in any stored field.
	assert.NotContains(t, string(f.Raw), "FAKEBODY")
	assert.NotContains(t, string(f.RawV2), "FAKEBODY")
	assert.NotContains(t, f.Redacted, "FAKEBODY")

	// The block region length must span the whole BEGIN..END block.
	assert.Equal(t, "block_bytes", firstKey(f.ExtraData))
	assert.Equal(t, len(pem), blockBytes(t, f.ExtraData))
}

// TestDetector_Scan_BackToBackBlocks_BlockBytesDoesNotSpanAdjacentKey is a
// regression test for the block-length measurement bug: when two full
// BEGIN/END PEM blocks sit back-to-back, the first block's block_bytes must
// only cover its own BEGIN..END span, never extend into the second key's
// header/body. See review section 04-detectors-d3.md LOW finding
// "private_key.go:56".
func TestDetector_Scan_BackToBackBlocks_BlockBytesDoesNotSpanAdjacentKey(t *testing.T) {
	firstBlock := "-----BEGIN RSA PRIVATE KEY-----\nFAKEBODY1\n-----END RSA PRIVATE KEY-----"
	secondBlock := "-----BEGIN EC PRIVATE KEY-----\nFAKEBODY2\n-----END EC PRIVATE KEY-----"
	pem := firstBlock + "\n" + secondBlock

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(pem))

	require.Len(t, findings, 2)
	assert.Equal(t, len(firstBlock), blockBytes(t, findings[0].ExtraData),
		"first block's block_bytes must not span into the second, unrelated key block")
	assert.Equal(t, len(secondBlock), blockBytes(t, findings[1].ExtraData))
}

// TestDetector_Scan_TwoBeginsNoEnd_BlockBytesCappedAtNextBegin covers the
// case where a BEGIN header has no END armor of its own before the next
// BEGIN header starts (e.g. a truncated/malformed first block): block_bytes
// must be capped at the next BEGIN rather than left unbounded or spanning
// into it.
func TestDetector_Scan_TwoBeginsNoEnd_BlockBytesCappedAtNextBegin(t *testing.T) {
	first := "-----BEGIN RSA PRIVATE KEY-----\n"
	second := "-----BEGIN EC PRIVATE KEY-----\n"
	pem := first + second

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(pem))

	require.Len(t, findings, 2)
	assert.Equal(t, len(first), blockBytes(t, findings[0].ExtraData))
}

// TestDetector_ScanViaMatcher_EncryptedPrivateKey_IsDetected is a
// testutil.ScanViaMatcher regression test proving the "ENCRYPTED PRIVATE
// KEY" armor survives the real Aho-Corasick matcher gate, i.e. that
// Keywords() was correctly broadened alongside the regex.
func TestDetector_ScanViaMatcher_EncryptedPrivateKey_IsDetected(t *testing.T) {
	input := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF...\n-----END ENCRYPTED PRIVATE KEY-----"

	d := &Detector{}
	findings := testutil.ScanViaMatcher(d, []byte(input))

	require.Len(t, findings, 1, "encrypted private key must survive the matcher gate")
	assert.Equal(t, "private-key", findings[0].DetectorID)
}

func firstKey(m map[string]string) string {
	for k := range m {
		return k
	}
	return ""
}

func blockBytes(t *testing.T, m map[string]string) int {
	t.Helper()
	v, ok := m["block_bytes"]
	assert.True(t, ok, "block_bytes must be present")
	n := 0
	for _, c := range v {
		n = n*10 + int(c-'0')
	}
	return n
}

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

const (
	testKeySID     = "SKabcdef0123456789abcdef0123456789"
	testAccountSID = "AC1234567890abcdef1234567890ABCDEF"
)

func syntheticSecret(seed string) string {
	return strings.Repeat(seed, 4)
}

func pairedFixture(secret string) string {
	return "TWILIO_ACCOUNT_SID=" + testAccountSID + "\n" +
		"TWILIO_API_KEY_SID=" + testKeySID + "\n" +
		"TWILIO_API_KEY_SECRET=" + secret
}

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "twilio-api-key", d.ID())
	assert.Equal(t, "Twilio API Key Secret", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.Empty(t, d.Keywords())
	assert.True(t, d.AuthoritativeOnOverlap())
}

func TestDetector_Scan_ReportsPairedSecretAndNonSecretContext(t *testing.T) {
	secret := syntheticSecret("Ab12Cd34")
	findings := (&Detector{}).Scan(context.Background(), []byte(pairedFixture(secret)))

	require.Len(t, findings, 1)
	assert.Equal(t, []byte(secret), findings[0].Raw)
	assert.Equal(t, "****"+secret[len(secret)-4:], findings[0].Redacted)
	assert.Equal(t, testKeySID, findings[0].ExtraData["api_key_sid"])
	assert.Equal(t, testAccountSID, findings[0].ExtraData["account_sid"])
	assert.NotContains(t, findings[0].ExtraData, "api_key_secret")
	for _, value := range findings[0].ExtraData {
		assert.NotEqual(t, secret, value, "secret must never be copied into ExtraData")
	}
}

func TestDetector_Scan_SupportsExplicitRoleVariants(t *testing.T) {
	secret := syntheticSecret("Qw12Er34")
	tests := []string{
		"TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_SECRET=" + secret,
		`{"twilioApiKeySid":"` + testKeySID + `","twilioApiKeySecret":"` + secret + `"}`,
		"twilio-api-key-sid=" + testKeySID + "\ntwilio-api-key-secret='" + secret + "'",
		`{"Twilio":{"ApiKeySid":"` + testKeySID + `","ApiKeySecret":"` + secret + `"}}`,
	}
	for i, input := range tests {
		findings := (&Detector{}).Scan(context.Background(), []byte(input))
		require.Lenf(t, findings, 1, "variant %d", i)
		assert.Equal(t, []byte(secret), findings[0].Raw)
	}
}

func TestDetector_ScanViaMatcher_PairedSecretIsDetected(t *testing.T) {
	secret := syntheticSecret("Zx98Cv76")
	findings := testutil.ScanViaMatcher(&Detector{}, []byte(pairedFixture(secret)))

	require.Len(t, findings, 1)
	assert.Equal(t, []byte(secret), findings[0].Raw)
}

func TestDetector_Scan_DoesNotReportBareIdentifiersOrUnpairedValues(t *testing.T) {
	secret := syntheticSecret("Ab12Cd34")
	tests := map[string]string{
		"bare API Key SID":               testKeySID,
		"bare Account SID":               testAccountSID,
		"labelled secret without SID":    "TWILIO_API_KEY_SECRET=" + secret,
		"SID with generic password":      "TWILIO_API_KEY_SID=" + testKeySID + "\nPASSWORD=" + secret,
		"secret role with short value":   "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=short",
		"secret role with long value":    "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=" + secret + "A",
		"secret role with hyphen suffix": "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=" + secret + "-extra",
		"ordinary placeholder":           "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=your_api_key_secret",
		"role embedded in identifier":    "TWILIO_API_KEY_SID=" + testKeySID + "\nNOTWILIO_API_KEY_SECRET=" + secret,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, (&Detector{}).Scan(context.Background(), []byte(input)))
		})
	}
}

func TestDetector_Scan_CompanionOutsideWindowIsNotPaired(t *testing.T) {
	secret := syntheticSecret("Ab12Cd34")
	input := "TWILIO_API_KEY_SID=" + testKeySID + strings.Repeat(" ", companionProximityWindow+1) +
		"TWILIO_API_KEY_SECRET=" + secret

	assert.Empty(t, (&Detector{}).Scan(context.Background(), []byte(input)))
}

func TestDetector_Scan_AssociatesNearestKeySID(t *testing.T) {
	secretA := syntheticSecret("Aa11Bb22")
	secretB := syntheticSecret("Cc33Dd44")
	keyA := "SKaaaaaaaa11111111aaaaaaaa11111111"
	keyB := "SKbbbbbbbb22222222bbbbbbbb22222222"
	input := "TWILIO_API_KEY_SID=" + keyA + "\nTWILIO_API_KEY_SECRET=" + secretA +
		strings.Repeat(" ", companionProximityWindow+1) +
		"TWILIO_API_KEY_SID=" + keyB + "\nTWILIO_API_KEY_SECRET=" + secretB

	findings := (&Detector{}).Scan(context.Background(), []byte(input))
	require.Len(t, findings, 2)
	assert.Equal(t, keyA, findings[0].ExtraData["api_key_sid"])
	assert.Equal(t, keyB, findings[1].ExtraData["api_key_sid"])
}

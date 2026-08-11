package twilio

import (
	"context"
	"fmt"
	"regexp"
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
	assert.Equal(t, []string{"secret"}, d.Keywords())
	assert.True(t, d.AuthoritativeOnOverlap())
	contract := d.PlaygroundPatternContract()
	require.Len(t, contract.Primary, 1)
	require.Len(t, contract.RequiredNearby, 1)
	assert.Equal(t, companionProximityWindow, contract.ProximityBytes)
	assert.True(t, contract.SameLogicalBlock)
	assert.True(t, contract.RejectPlaceholders)
	assert.True(t, contract.OneToOne)
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
	assert.Equal(t, secret, pairedFixture(secret)[findings[0].ByteStart:findings[0].ByteEnd])
	for _, value := range findings[0].ExtraData {
		assert.NotEqual(t, secret, value, "secret must never be copied into ExtraData")
	}
}

func TestDetector_Scan_SupportsExplicitRoleVariants(t *testing.T) {
	tests := []struct {
		input  string
		secret string
	}{
		{input: "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_SECRET=x7-K", secret: "x7-K"},
		{input: `{"twilioApiKeySid":"` + testKeySID + `","twilioApiKeySecret":"opaque/+value=="}`, secret: "opaque/+value=="},
		{input: "twilio-api-key-sid=" + testKeySID + "\ntwilio-api-key-secret='Secret.with.punctuation_42'", secret: "Secret.with.punctuation_42"},
		{input: `{"Twilio":{"ApiKeySid":"` + testKeySID + `","ApiKeySecret":"` + syntheticSecret("Qw12Er34") + `"}}`, secret: syntheticSecret("Qw12Er34")},
		{input: "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=real-example-secret-value-42", secret: "real-example-secret-value-42"},
		{input: "MYAPP_TWILIO_API_KEY_SID=" + testKeySID + "\nMYAPP_TWILIO_API_KEY_SECRET=" + syntheticSecret("Mn12Bv34"), secret: syntheticSecret("Mn12Bv34")},
		{input: "PROD_TWILIO_API_KEY_SID=" + testKeySID + "\nPROD_TWILIO_API_KEY_SECRET=" + syntheticSecret("Rt56Yu78"), secret: syntheticSecret("Rt56Yu78")},
		{input: "X_API_KEY_SID=" + testKeySID + "\nX_API_KEY_SECRET=" + syntheticSecret("Kp90Lm12"), secret: syntheticSecret("Kp90Lm12")},
		{input: "environment:\n  - TWILIO_API_KEY_SID=" + testKeySID + "\n  - TWILIO_API_KEY_SECRET=" + syntheticSecret("Dc34Fv56"), secret: syntheticSecret("Dc34Fv56")},
	}
	for i, test := range tests {
		findings := (&Detector{}).Scan(context.Background(), []byte(test.input))
		require.Lenf(t, findings, 1, "variant %d", i)
		assert.Equal(t, []byte(test.secret), findings[0].Raw)
		assert.Equal(t, test.secret, test.input[findings[0].ByteStart:findings[0].ByteEnd])
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
		"bare SID beside secret":         testKeySID + "\nTWILIO_API_KEY_SECRET=" + secret,
		"SID under unrelated role":       "ID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=" + secret,
		"SID with generic password":      "TWILIO_API_KEY_SID=" + testKeySID + "\nPASSWORD=" + secret,
		"other provider secret role":     "TWILIO_API_KEY_SID=" + testKeySID + "\nSTRIPE_API_SECRET=" + secret,
		"ordinary placeholder":           "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=your_api_key_secret",
		"canonical Twilio placeholder":   "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=YOUR_TWILIO_API_KEY_SECRET",
		"external secret reference":      "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=${TWILIO_API_KEY_SECRET}",
		"separate logical block":         "TWILIO_API_KEY_SID=" + testKeySID + "\n\nTWILIO_API_KEY_SECRET=" + secret,
		"separate JSON objects":          `{"ApiKeySid":"` + testKeySID + `"},{"ApiKeySecret":"` + secret + `"}`,
		"role embedded in identifier":    "TWILIO_API_KEY_SID=" + testKeySID + "\nNOTWILIO_API_KEY_SECRET=" + secret,
		"escaped quote is not truncated": `{"ApiKeySid":"` + testKeySID + `","ApiKeySecret":"opaque\"tail"}`,
		"overlong unquoted secret":       "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=" + strings.Repeat("a", 513),
		"hyphen suffixed SID":            "TWILIO_API_KEY_SID=" + testKeySID + "-not-a-real-sid\nTWILIO_API_KEY_SECRET=" + secret,
		"dot suffixed SID":               "TWILIO_API_KEY_SID=" + testKeySID + ".suffix\nTWILIO_API_KEY_SECRET=" + secret,
		"quoted suffixed SID":            `{"ApiKeySid":"` + testKeySID + `-suffix","ApiKeySecret":"` + secret + `"}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, (&Detector{}).Scan(context.Background(), []byte(input)))
		})
	}
}

func TestDetector_ScanViaMatcher_RejectsTemplatesAndMalformedSID(t *testing.T) {
	secret := syntheticSecret("Ab12Cd34")
	for name, input := range map[string]string{
		"uppercase canonical placeholder": "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=YOUR_TWILIO_API_KEY_SECRET",
		"lowercase canonical placeholder": "TWILIO_API_KEY_SID=" + testKeySID + "\nTWILIO_API_KEY_SECRET=your_twilio_api_key_secret",
		"hyphen suffixed SID":             "TWILIO_API_KEY_SID=" + testKeySID + "-suffix\nTWILIO_API_KEY_SECRET=" + secret,
		"dot suffixed SID":                "TWILIO_API_KEY_SID=" + testKeySID + ".suffix\nTWILIO_API_KEY_SECRET=" + secret,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, testutil.ScanViaMatcher(&Detector{}, []byte(input)))
		})
	}
}

func TestDetector_Scan_CompanionOutsideWindowIsNotPaired(t *testing.T) {
	secret := syntheticSecret("Ab12Cd34")
	input := "TWILIO_API_KEY_SID=" + testKeySID + strings.Repeat(" ", companionProximityWindow+128) +
		"TWILIO_API_KEY_SECRET=" + secret

	assert.Empty(t, (&Detector{}).Scan(context.Background(), []byte(input)))
}

func TestDetector_Scan_ProximityUsesUTF8Bytes(t *testing.T) {
	secret := "opaque-real-value-42"
	tests := []struct {
		name string
		gap  string
		want int
	}{
		{name: "ASCII 512", gap: "\n" + strings.Repeat("a", 510) + " ", want: 1},
		{name: "ASCII 513", gap: "\n" + strings.Repeat("a", 511) + " ", want: 0},
		{name: "two-byte Unicode 512", gap: "\n" + strings.Repeat("é", 255) + " ", want: 1},
		{name: "two-byte Unicode over limit", gap: "\n" + strings.Repeat("é", 256) + " ", want: 0},
		{name: "astral Unicode 512", gap: "\n" + strings.Repeat("🔐", 127) + "   ", want: 1},
		{name: "astral Unicode 513", gap: "\n" + strings.Repeat("🔐", 127) + "    ", want: 0},
		{name: "CRLF 512", gap: "\r\n" + strings.Repeat("a", 509) + " ", want: 1},
		{name: "CRLF 513", gap: "\r\n" + strings.Repeat("a", 510) + " ", want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := "TWILIO_API_KEY_SID=" + testKeySID + test.gap + "TWILIO_API_KEY_SECRET=" + secret
			assert.Len(t, (&Detector{}).Scan(context.Background(), []byte(input)), test.want)
		})
	}
}

func TestDetector_Scan_AssociatesNearestKeySID(t *testing.T) {
	secretA := syntheticSecret("Aa11Bb22")
	secretB := syntheticSecret("Cc33Dd44")
	keyA := "SKaaaaaaaa11111111aaaaaaaa11111111"
	keyB := "SKbbbbbbbb22222222bbbbbbbb22222222"
	input := "TWILIO_API_KEY_SID=" + keyA + "\nTWILIO_API_KEY_SECRET=" + secretA +
		strings.Repeat(" ", companionProximityWindow+128) +
		"TWILIO_API_KEY_SID=" + keyB + "\nTWILIO_API_KEY_SECRET=" + secretB

	findings := (&Detector{}).Scan(context.Background(), []byte(input))
	require.Len(t, findings, 2)
	assert.Equal(t, keyA, findings[0].ExtraData["api_key_sid"])
	assert.Equal(t, keyB, findings[1].ExtraData["api_key_sid"])
}

func TestDetector_Scan_ConsecutivePairsAreNotSuppressedOnTies(t *testing.T) {
	var input strings.Builder
	wantSIDs := make([]string, 0, 5)
	for i := range 5 {
		keySID := fmt.Sprintf("SK%032x", i+1)
		secret := fmt.Sprintf("opaque-secret-%d-Q7mN2pL9rT4vW8xY", i+1)
		wantSIDs = append(wantSIDs, keySID)
		fmt.Fprintf(&input, "TWILIO_API_KEY_SID=%s\nTWILIO_API_KEY_SECRET=%s\n", keySID, secret)
	}

	findings := testutil.ScanViaMatcher(&Detector{}, []byte(input.String()))
	require.Len(t, findings, len(wantSIDs))
	for i, got := range findings {
		assert.Equal(t, wantSIDs[i], got.ExtraData["api_key_sid"])
	}
}

func TestDetector_Scan_DoesNotReuseOneSIDForMultipleSecrets(t *testing.T) {
	input := "TWILIO_API_KEY_SID=" + testKeySID + "\n" +
		"TWILIO_API_KEY_SECRET=first-opaque-secret\n" +
		"TWILIO_API_KEY_SECRET=second-opaque-secret"

	findings := (&Detector{}).Scan(context.Background(), []byte(input))
	require.Len(t, findings, 1)
	assert.Equal(t, []byte("first-opaque-secret"), findings[0].Raw)
}

func TestDetector_Scan_ExactSpanSelectsAcceptedOccurrence(t *testing.T) {
	secret := syntheticSecret("Aa12Bb34")
	input := "NOTE=" + secret + " # rejected duplicate\n" + pairedFixture(secret)

	findings := (&Detector{}).Scan(context.Background(), []byte(input))
	require.Len(t, findings, 1)
	assert.Equal(t, strings.LastIndex(input, secret), findings[0].ByteStart)
	assert.Equal(t, secret, input[findings[0].ByteStart:findings[0].ByteEnd])
}

func TestAssignmentMatches_FailsClosedOnMissingOrEmptyCapture(t *testing.T) {
	assert.Empty(t, assignmentMatches(regexp.MustCompile(`x`), []byte("x")))
	assert.Empty(t, assignmentMatches(regexp.MustCompile(`x(y)?`), []byte("x")))
	assert.Empty(t, assignmentMatches(regexp.MustCompile(`x()`), []byte("x")))

	matches := assignmentMatches(regexp.MustCompile(`x(y)`), []byte("xy"))
	require.Len(t, matches, 1)
	assert.Equal(t, assignmentMatch{wholeStart: 0, wholeEnd: 2, valueStart: 1, valueEnd: 2}, matches[0])

	assert.Empty(t, assignmentMatches(twilioKeySIDAssignmentPattern, []byte("TWILIO_API_KEY_SID="+testKeySID+"-suffix")))
	assert.Empty(t, assignmentMatches(twilioAccountSIDAssignmentPattern, []byte("TWILIO_ACCOUNT_SID="+testAccountSID+".suffix")))
}

func TestCompanionSelection_PrefersPrecedingOnTieAndRejectsInvalidBlocks(t *testing.T) {
	data := []byte(strings.Repeat(" ", 200))
	target := assignmentMatch{wholeStart: 100, wholeEnd: 110, valueStart: 105, valueEnd: 110}
	candidates := []assignmentMatch{
		{wholeStart: 80, wholeEnd: 90, valueStart: 80, valueEnd: 90},
		{wholeStart: 120, wholeEnd: 130, valueStart: 120, valueEnd: 130},
	}
	assert.Equal(t, 0, nearestUnusedCompanion(data, target, candidates, []bool{false, false}))
	assert.Equal(t, 1, nearestUnusedCompanion(data, target, candidates, []bool{true, false}))

	assert.False(t, sameLogicalBlock(data, assignmentMatch{wholeStart: -1, wholeEnd: -1}, target))
	assert.Equal(t, 0, rangeGap(target, assignmentMatch{wholeStart: 105, wholeEnd: 115}))
}

func TestIsNonSecretValue_ReferenceAndPlaceholderMatrix(t *testing.T) {
	for _, value := range []string{
		"change-me", "NOT_A_REAL_SECRET", "replace_me", "${SECRET}", "$SECRET",
		"{{ secret }}", "%SECRET%", "<secret>", "vault://path", "op://vault/item",
		"secret://path", "file://path", "/run/secrets/token", "@Microsoft.KeyVault(...)集",
		"****", "0000", "----",
	} {
		assert.Truef(t, isNonSecretValue(value), "%q", value)
	}
	assert.False(t, isNonSecretValue("opaque-real-value-42"))
}

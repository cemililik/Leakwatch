package snowflake

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/HodeTech/leakwatch/internal/detector"
	snowflakedetector "github.com/HodeTech/leakwatch/internal/detector/snowflake"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/require"
)

func TestVerify_RealDetectorOutput_ValidatesPairedConnection(t *testing.T) {
	fixture := testutil.RegisteredDetectorFixtures()[detectorID]
	findings := testutil.ScanViaMatcher(&snowflakedetector.Detector{}, fixture.Input)
	require.Len(t, findings, 1)
	require.NotEmpty(t, findings[0].RawV2)
	result := (&Verifier{}).Verify(t.Context(), findings[0])
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
}

func TestVerifier_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "snowflake-credentials", v.Type())
}

func TestVerify_ValidCredentials_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("MyStr0ngP@ssword!"),
		RawV2:      []byte("account.snowflakecomputing.com/?password=MyStr0ngP@ssword!"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	// Format-only verifier: a valid format does not prove the credential is
	// active, so the status must be Unverified, never VerifiedActive.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
}

func TestVerify_EmptyInput_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty credentials", result.Message)
}

func TestVerify_ShortPassword_ReturnsUnverifiedFormatInvalid(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("simple"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	// Format invalid must NOT be reported as VerifiedInactive: we never
	// contacted the provider.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_NotSnowflakeConnString_ReturnsUnverifiedFormatInvalid(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("MyStr0ngP@ssword!"),
		RawV2:      []byte("postgres://user:pass@db.example.com:5432/app"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

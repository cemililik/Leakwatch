package twilio

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	twiliodetector "github.com/HodeTech/leakwatch/internal/detector/twilio"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fixtureAPIKeySID = "SKabcdef0123456789abcdef0123456789"
	fixtureAccount   = "AC1234567890abcdef1234567890ABCDEF"
)

func fixtureAPIKeySecret() string { return strings.Repeat("Ab12Cd34", 4) }

func detectorFixture(t *testing.T, includeAccount bool) detector.RawFinding {
	t.Helper()
	input := "TWILIO_API_KEY_SID=" + fixtureAPIKeySID + "\n"
	if includeAccount {
		input = "TWILIO_ACCOUNT_SID=" + fixtureAccount + "\n" + input
	}
	input += "TWILIO_API_KEY_" + "SECRET=" + fixtureAPIKeySecret()
	findings := (&twiliodetector.Detector{}).Scan(context.Background(), []byte(input))
	require.Len(t, findings, 1)
	return findings[0]
}

func TestVerify_RealDetectorFinding_ReachesTrustedProbe(t *testing.T) {
	secret := fixtureAPIKeySecret()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2010-04-01/Accounts/"+fixtureAccount+".json", r.URL.Path)
		auth := r.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(auth, "Basic "))
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		require.NoError(t, err)
		assert.Equal(t, fixtureAPIKeySID+":"+secret, string(decoded))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sid":"` + fixtureAccount + `"}`))
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
		context.Background(), detectorFixture(t, true),
	)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, fixtureAccount, result.ExtraData["account_sid"])
	assert.NotContains(t, result.Message, secret)
	for _, value := range result.ExtraData {
		assert.NotEqual(t, secret, value)
	}
}

func TestVerify_ProductionFindingWithoutTrustedOrigin_IsUnverified(t *testing.T) {
	result := (&Verifier{}).Verify(context.Background(), detectorFixture(t, true))

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "trusted Twilio regional API origin is not configured", result.Message)
}

func TestVerify_Only401IsInactive_403IsPermissionError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   finding.VerificationStatus
	}{
		{name: "authentication rejection", status: http.StatusUnauthorized, want: finding.StatusVerifiedInactive},
		{name: "permission rejection", status: http.StatusForbidden, want: finding.StatusVerifyError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
				context.Background(), detectorFixture(t, true),
			)
			assert.Equal(t, tc.want, result.Status)
		})
	}
}

func TestVerify_NoAccountSID_UsesCollectionProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2010-04-01/Accounts.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accounts":[]}`))
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
		context.Background(), detectorFixture(t, false),
	)
	assert.Equal(t, finding.StatusVerifiedActive, result.Status)
}

func TestVerify_MissingOrInvalidCompanionContext_IsUnverified(t *testing.T) {
	secret := fixtureAPIKeySecret()
	tests := []detector.RawFinding{
		{Raw: []byte(secret)},
		{Raw: []byte(secret), ExtraData: map[string]string{"api_key_sid": "not-a-sid"}},
		{Raw: []byte(secret), ExtraData: map[string]string{"api_key_sid": fixtureAPIKeySID, "account_sid": "not-an-account"}},
	}
	for _, raw := range tests {
		result := (&Verifier{apiURL: "http://127.0.0.1:1"}).Verify(context.Background(), raw)
		assert.Equal(t, finding.StatusUnverified, result.Status)
	}
}

func TestVerify_MalformedSuccessResponse_IsVerifyError(t *testing.T) {
	tests := []struct {
		contentType string
		body        string
	}{
		{contentType: "application/json", body: `{}`},
		{contentType: "text/html", body: `{"sid":"` + fixtureAccount + `"}`},
		{contentType: "application/json", body: `{"sid":"ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`},
	}
	for _, tc := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", tc.contentType)
			_, _ = w.Write([]byte(tc.body))
		}))
		result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
			context.Background(), detectorFixture(t, true),
		)
		server.Close()
		assert.Equal(t, finding.StatusVerifyError, result.Status)
	}
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
		context.Background(), detectorFixture(t, true),
	)
	assert.Equal(t, finding.StatusVerifyError, result.Status)
}

func TestVerify_TypeAndEmptyToken(t *testing.T) {
	assert.Equal(t, detectorID, (&Verifier{}).Type())
	result := (&Verifier{}).Verify(context.Background(), detector.RawFinding{})
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
}

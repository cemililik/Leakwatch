package twilio

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Fixtures mirror the real Twilio detector output: raw.Raw is the API Key SID
// ("SK" + 32 hex) and ExtraData["account_sid"] is the Account SID ("AC" + 32
// hex). The API Key Secret is the paired secret required to authenticate.
const (
	fixtureAPIKeySID = "SKabcdef0123456789abcdef0123456789"
	fixtureAccount   = "AC1234567890abcdef1234567890abcd"
	fixtureSecret    = "api_key_secret_0123456789abcdef0"
)

func TestVerify_ValidKey_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2010-04-01/Accounts/"+fixtureAccount+".json", r.URL.Path)

		// Verify Basic auth: API Key SID as username, API Key Secret as password.
		auth := r.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(auth, "Basic "))
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		require.NoError(t, err)
		parts := strings.SplitN(string(decoded), ":", 2)
		assert.Equal(t, fixtureAPIKeySID, parts[0])
		assert.Equal(t, fixtureSecret, parts[1])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sid":"` + fixtureAccount + `"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(fixtureAPIKeySID),
		Redacted:   "SK****6789",
		ExtraData: map[string]string{
			"account_sid":    fixtureAccount,
			"api_key_secret": fixtureSecret,
		},
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Twilio API key is active", result.Message)
}

func TestVerify_InvalidKey_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Authenticate"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(fixtureAPIKeySID),
		Redacted:   "SK****6789",
		ExtraData: map[string]string{
			"account_sid":    fixtureAccount,
			"api_key_secret": fixtureSecret,
		},
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Twilio API key is invalid or revoked", result.Message)
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(fixtureAPIKeySID),
		Redacted:   "SK****6789",
		ExtraData: map[string]string{
			"account_sid":    fixtureAccount,
			"api_key_secret": fixtureSecret,
		},
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

// TestVerify_NoAPIKeySecret_ReturnsUnverified verifies that the common real
// detector output (API Key SID + Account SID, but no paired secret) is reported
// as Unverified — never falsely inactive.
func TestVerify_NoAPIKeySecret_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(fixtureAPIKeySID),
		Redacted:   "SK****6789",
		ExtraData:  map[string]string{"account_sid": fixtureAccount},
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "API Key Secret unavailable; cannot verify", result.Message)
}

// TestVerify_NoAccountSID_UsesCollectionEndpoint verifies that the request
// falls back to the accounts collection when no Account SID is known.
func TestVerify_NoAccountSID_UsesCollectionEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2010-04-01/Accounts.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accounts":[]}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(fixtureAPIKeySID),
		Redacted:   "SK****6789",
		ExtraData:  map[string]string{"api_key_secret": fixtureSecret},
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedActive, result.Status)
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "twilio-api-key", v.Type())
}

func TestVerify_EmptyToken_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
}

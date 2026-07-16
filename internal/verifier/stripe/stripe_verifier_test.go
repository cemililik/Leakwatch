package stripe

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

func TestLiveKeyVerifier_ValidKey_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/balance", r.URL.Path)

		// Verify Basic auth: token as username, empty password.
		auth := r.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(auth, "Basic "))
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		require.NoError(t, err)
		parts := strings.SplitN(string(decoded), ":", 2)
		assert.Equal(t, "sk_live_abcdef1234567890abcdef12", parts[0])
		assert.Equal(t, "", parts[1])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"available":[{"amount":1000,"currency":"usd"}]}`))
	}))
	defer server.Close()

	v := &LiveKeyVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: liveDetectorID,
		Raw:        []byte("sk_live_abcdef1234567890abcdef12"),
		Redacted:   "sk_live_****ef12",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Stripe live API key is active", result.Message)
	assert.Equal(t, "live", result.ExtraData["key_type"])
}

func TestTestKeyVerifier_ValidKey_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/balance", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"available":[{"amount":0,"currency":"usd"}]}`))
	}))
	defer server.Close()

	v := &TestKeyVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: testDetectorID,
		Raw:        []byte("sk_test_abcdef1234567890abcdef12"),
		Redacted:   "sk_test_****ef12",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Stripe test API key is active", result.Message)
	assert.Equal(t, "test", result.ExtraData["key_type"])
}

func TestLiveKeyVerifier_InvalidKey_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid API Key provided"}}`))
	}))
	defer server.Close()

	v := &LiveKeyVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: liveDetectorID,
		Raw:        []byte("sk_live_invalidkey1234567890abcd"),
		Redacted:   "sk_live_****abcd",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Stripe live API key is invalid or revoked", result.Message)
}

func TestLiveKeyVerifier_RestrictedKeyWithoutBalanceScope_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/balance", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"This API Key does not have permissions to perform this request","type":"invalid_request_error"}}`))
	}))
	defer server.Close()

	v := &LiveKeyVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: liveDetectorID,
		Raw:        []byte("rk_live_restrictedkey1234567890abcd"),
		Redacted:   "rk_live_****abcd",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status,
		"a 403 from a restricted key means it authenticated, just lacks scope; it must not be a hard verify error")
	assert.Equal(t, "Stripe live API key is active", result.Message)
	assert.Equal(t, "restricted", result.ExtraData["scope"])
	assert.Equal(t, "live", result.ExtraData["key_type"])
}

func TestLiveKeyVerifier_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := &LiveKeyVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: liveDetectorID,
		Raw:        []byte("sk_live_somekey12345678901234abcd"),
		Redacted:   "sk_live_****abcd",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestLiveKeyVerifier_Type_ReturnsCorrectID(t *testing.T) {
	v := &LiveKeyVerifier{}
	assert.Equal(t, "stripe-api-key-live", v.Type())
}

func TestTestKeyVerifier_Type_ReturnsCorrectID(t *testing.T) {
	v := &TestKeyVerifier{}
	assert.Equal(t, "stripe-api-key-test", v.Type())
}

func TestLiveKeyVerifier_EmptyToken_ReturnsUnverified(t *testing.T) {
	v := &LiveKeyVerifier{}

	raw := detector.RawFinding{
		DetectorID: liveDetectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
}

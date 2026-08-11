package supabase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_ValidKey_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/projects", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id":"project-123","name":"my-project"}]`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("sbp_abcdef1234567890abcdef1234567890abcdef"),
		Redacted:   "sbp_****cdef",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Supabase personal access token is active", result.Message)
}

func TestVerify_InvalidKey_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("sbp_invalidkey12345678901234567890abcdef"),
		Redacted:   "sbp_****cdef",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Supabase personal access token is invalid or revoked", result.Message)
}

func TestVerify_Forbidden_RemainsInconclusive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
	}))
	defer server.Close()

	v := &Verifier{apiURL: server.URL, httpClient: server.Client()}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("synthetic-sbp-token")})

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.NotEqual(t, finding.StatusVerifiedInactive, result.Status)
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("sbp_somekey1234567890abcdef123456789012"),
		Redacted:   "sbp_****9012",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "supabase-service-key", v.Type())
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

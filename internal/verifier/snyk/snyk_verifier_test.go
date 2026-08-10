package snyk

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
		assert.Equal(t, "/rest/self", r.URL.Path)
		// The Snyk REST API requires the version as a query parameter.
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))
		assert.Equal(t, "token test-snyk-api-key-abcdef1234567890", r.Header.Get("Authorization"))
		assert.Equal(t, "2024-10-15", r.Header.Get("Version"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"type":"user","id":"abc-123"}}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("test-snyk-api-key-abcdef1234567890"),
		Redacted:   "****7890",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Snyk API key is active", result.Message)
}

func TestVerify_InvalidKey_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"Invalid auth token provided"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("invalid-snyk-key-123456789012345678"),
		Redacted:   "****5678",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Snyk API key is invalid or revoked", result.Message)
}

func TestVerify_ForbiddenKey_ReturnsVerifyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":403,"message":"Forbidden"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("forbidden-snyk-key-12345678901234567"),
		Redacted:   "****4567",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "403")
}

func TestVerify_MalformedSuccessResponse_ReturnsVerifyError(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "missing data", contentType: "application/vnd.api+json", body: `{}`},
		{name: "null data", contentType: "application/json", body: `{"data":null}`},
		{name: "wrong content type", contentType: "text/plain", body: `{"data":{}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
				context.Background(), detector.RawFinding{Raw: []byte("synthetic-snyk-key")},
			)
			assert.Equal(t, finding.StatusVerifyError, result.Status)
		})
	}
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"message":"Internal server error"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("some-snyk-key-1234567890123456789012"),
		Redacted:   "****9012",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "snyk-api-key", v.Type())
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

func TestVerify_WithoutTrustedOrigin_MakesNoRequest(t *testing.T) {
	v := &Verifier{}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("synthetic-snyk-key")})

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "trusted Snyk API origin is not configured", result.Message)
}

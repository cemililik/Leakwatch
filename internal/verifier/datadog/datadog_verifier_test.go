package datadog

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
		assert.Equal(t, "/api/v1/validate", r.URL.Path)
		assert.NotEmpty(t, r.Header.Get("DD-API-KEY"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"valid": true}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("abcdef1234567890abcdef1234567890"),
		Redacted:   "abcd****7890",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Datadog API key is active", result.Message)
}

func TestVerify_InvalidKey_200False_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"valid": false}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("invalidkey12345678901234567890ab"),
		Redacted:   "inva****90ab",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Datadog API key is invalid", result.Message)
}

func TestVerify_MalformedSuccessResponse_ReturnsVerifyError(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "missing valid", contentType: "application/json", body: `{}`},
		{name: "null body", contentType: "application/json", body: `null`},
		{name: "wrong content type", contentType: "text/plain", body: `{"valid":true}`},
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
				context.Background(), detector.RawFinding{Raw: []byte("synthetic-datadog-key")},
			)
			assert.Equal(t, finding.StatusVerifyError, result.Status)
		})
	}
}

func TestVerify_InvalidKey_403_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["Forbidden"]}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("invalidkey12345678901234567890ab"),
		Redacted:   "inva****90ab",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Datadog API key is invalid or revoked", result.Message)
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":["Internal server error"]}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("somekey1234567890abcdef12345678"),
		Redacted:   "some****5678",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "datadog-api-key", v.Type())
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

func TestVerify_WithoutTrustedSite_MakesNoRequest(t *testing.T) {
	v := &Verifier{}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("synthetic-datadog-key")})

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "trusted Datadog site is not configured", result.Message)
}

func TestNewForTrustedInstance_AcceptsOnlyOfficialDatadogSites(t *testing.T) {
	for _, origin := range []string{
		"https://api.datadoghq.com", "https://api.datadoghq.eu", "https://api.ap2.datadoghq.com",
		"https://api.ddog-gov.com", "https://api.us2.ddog-gov.com",
	} {
		configured, err := NewForTrustedInstance(origin)
		require.NoError(t, err, origin)
		assert.Equal(t, origin, configured.apiURL)
	}
	for _, origin := range []string{
		"https://datadoghq.com", "https://api.datadoghq.com.attacker.example",
		"https://api.datadoghq.com:443", "http://api.datadoghq.com",
	} {
		_, err := NewForTrustedInstance(origin)
		assert.Error(t, err, origin)
	}
}

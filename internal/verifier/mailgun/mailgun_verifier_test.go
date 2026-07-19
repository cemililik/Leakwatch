package mailgun

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
		assert.Equal(t, "/v3/domains", r.URL.Path)

		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "api", username)
		assert.NotEmpty(t, password)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"total_count":2,"items":[{"name":"example.com"},{"name":"mail.example.com"}]}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		euAPIURL:   server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("key-abcdef1234567890abcdef1234567890"),
		Redacted:   "key-****7890",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Mailgun API key is active", result.Message)
}

// TestVerify_InvalidOnBothHosts_ReturnsInactive asserts that a key rejected by
// both the US and EU hosts (the fallback exhausted) is genuinely inactive.
func TestVerify_InvalidOnBothHosts_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`Forbidden`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		euAPIURL:   server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("key-invalidkey1234567890abcdef12345678"),
		Redacted:   "key-****5678",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Mailgun API key is invalid or revoked", result.Message)
}

// TestVerify_InactiveOnUSHost_FallsBackToEUHost_ReturnsActive asserts that a
// key valid only on the EU-region host is not misreported as inactive just
// because the US host (probed first) rejects it.
func TestVerify_InactiveOnUSHost_FallsBackToEUHost_ReturnsActive(t *testing.T) {
	usServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`Forbidden`))
	}))
	defer usServer.Close()

	euServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v3/domains", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"total_count":1,"items":[{"name":"example.eu"}]}`))
	}))
	defer euServer.Close()

	v := &Verifier{
		apiURL:     usServer.URL,
		euAPIURL:   euServer.URL,
		httpClient: usServer.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("key-euonlykey1234567890abcdef1234567890"),
		Redacted:   "key-****7890",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status,
		"an EU-only key must not be misreported as inactive just because the US host rejects it")
	assert.Equal(t, "Mailgun API key is active", result.Message)
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		euAPIURL:   server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("key-somekey1234567890abcdef1234567890"),
		Redacted:   "key-****7890",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "mailgun-api-key", v.Type())
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

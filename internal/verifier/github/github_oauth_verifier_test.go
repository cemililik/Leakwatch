package github

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

func TestOAuthVerify_ValidToken_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer server.Close()

	v := &OAuthVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: oauthDetectorID,
		Raw:        []byte("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"),
		Redacted:   "gho_****ef12",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "GitHub OAuth token is active", result.Message)
	assert.Equal(t, "octocat", result.ExtraData["login"])
}

func TestOAuthVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	v := &OAuthVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: oauthDetectorID,
		Raw:        []byte("gho_invalidtoken1234567890123456789012"),
		Redacted:   "gho_****9012",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "GitHub OAuth token is invalid or revoked", result.Message)
}

func TestOAuthVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"Internal server error"}`))
	}))
	defer server.Close()

	v := &OAuthVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: oauthDetectorID,
		Raw:        []byte("gho_sometoken12345678901234567890123456"),
		Redacted:   "gho_****3456",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

// TestOAuthVerify_Forbidden_ReturnsVerifyError documents the behaviour for a
// GitHub stateless installation token (ghs_): such tokens authenticate as an app
// installation, not a user, so GET /user answers 403 ("Resource not accessible
// by integration"). 403 is neither an active (200) nor an inactive (401) status,
// so it maps to a verify error — a live installation token is never mislabelled
// "active" or "invalid or revoked".
func TestOAuthVerify_Forbidden_ReturnsVerifyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
	}))
	defer server.Close()

	v := &OAuthVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: oauthDetectorID,
		// Obviously-fake stateless-shaped token (ghs_APPID_<jwt>), assembled so
		// no contiguous real-looking literal is committed.
		Raw:      []byte("ghs_42_" + "eyJhdg" + "." + "eyJbody" + "." + "sig123456"),
		Redacted: "****3456",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "403")
}

func TestOAuthVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &OAuthVerifier{}
	assert.Equal(t, "github-oauth-token", v.Type())
}

func TestOAuthVerify_EmptyToken_ReturnsUnverified(t *testing.T) {
	v := &OAuthVerifier{}

	raw := detector.RawFinding{
		DetectorID: oauthDetectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
}

func TestOAuthVerify_MalformedJSON_ReturnsVerifyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	v := &OAuthVerifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: oauthDetectorID,
		Raw:        []byte("gho_somevalidtoken123456789012345678901"),
		Redacted:   "gho_****8901",
	}

	result := v.Verify(context.Background(), raw)

	// A 200 whose body cannot be decoded must not be claimed as active: we
	// cannot confirm the expected response shape.
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "failed to decode response body")
}

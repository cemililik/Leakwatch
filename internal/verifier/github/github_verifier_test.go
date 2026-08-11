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

func TestVerify_ValidToken_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/user", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"login":"octocat","id":1}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"),
		Redacted:   "ghp_****ef12",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "GitHub token is active", result.Message)
	assert.Equal(t, "octocat", result.ExtraData["login"])
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("ghp_invalidtoken123456789012345678901"),
		Redacted:   "ghp_****8901",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "GitHub token is invalid or revoked", result.Message)
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
		Raw:        []byte("ghp_sometoken12345678901234567890123"),
		Redacted:   "ghp_****0123",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "github-token", v.Type())
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
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("synthetic-github-token")})

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "trusted GitHub API origin is not configured", result.Message)
}

func TestVerify_MissingIdentityOrWrongContentType_ReturnsVerifyError(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "missing login", contentType: "application/json", body: `{}`},
		{name: "wrong content type", contentType: "text/html", body: `{"login":"octocat"}`},
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
				context.Background(), detector.RawFinding{Raw: []byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12")},
			)
			assert.Equal(t, finding.StatusVerifyError, result.Status)
		})
	}
}

func TestNewForTrustedInstance_ValidatesOrigin(t *testing.T) {
	configured, err := NewForTrustedInstance("https://api.github.example/")
	require.NoError(t, err)
	assert.Equal(t, "https://api.github.example", configured.apiURL)
	for _, origin := range []string{"http://api.github.com", "https://127.0.0.1", "https://localhost", "https://github.example/path"} {
		_, err := NewForTrustedInstance(origin)
		assert.Error(t, err, origin)
	}
}

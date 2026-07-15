package auth0

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// makeJWT builds a syntactically valid (but unsigned) JWT carrying the given
// iss claim. The signature segment is a placeholder — the verifier never checks
// it, so no real signing is needed for these tests.
func makeJWT(iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `"}`))
	return header + "." + payload + ".c2lnbmF0dXJl"
}

func TestVerify_ValidToken_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v2/", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyJ9.signature"),
		Redacted:   "eyJh****ture",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Auth0 management token is active", result.Message)
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"statusCode":401,"error":"Unauthorized","message":"Invalid token"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.invalid.token"),
		Redacted:   "eyJh****oken",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Auth0 management token is invalid or expired", result.Message)
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
		Raw:        []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.some.token"),
		Redacted:   "eyJh****oken",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "auth0-management-token", v.Type())
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

func TestVerify_NonJWTToken_ReturnsUnverified(t *testing.T) {
	// No apiURL override: the verifier must derive the tenant from the token
	// itself. A non-JWT token cannot be routed, so the result is indeterminate
	// (StatusUnverified) — never a false "invalid".
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("not-a-jwt-token-value-1234567890"),
		Redacted:   "not-****7890",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "tenant domain")
}

func TestVerify_TenantHostDerivedFromIssClaim(t *testing.T) {
	var gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		assert.Equal(t, "/api/v2/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// The iss claim points the verifier at the test server; apiURL is left
	// unset so the iss-decoding path (not the test override) is exercised.
	v := &Verifier{httpClient: server.Client()}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(makeJWT(server.URL + "/")),
		Redacted:   "eyJh****ture",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.NotEmpty(t, gotHost)
}

func TestIssuerFromJWT(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantIss string
		wantOK  bool
	}{
		{
			name:    "valid JWT with iss",
			token:   makeJWT("https://acme.eu.auth0.com/"),
			wantIss: "https://acme.eu.auth0.com/",
			wantOK:  true,
		},
		{
			name:   "not a JWT (single segment)",
			token:  "plaintextsecret",
			wantOK: false,
		},
		{
			name:   "wrong segment count",
			token:  "a.b.c.d",
			wantOK: false,
		},
		{
			name:   "JWT without iss claim",
			token:  makeJWT(""),
			wantOK: false,
		},
		{
			name:   "invalid base64 payload",
			token:  "aaa.!!!not-base64!!!.ccc",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iss, ok := issuerFromJWT(tt.token)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantIss, iss)
		})
	}
}

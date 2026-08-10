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
		assert.Equal(t, "/api/v2/clients", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("per_page"))
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
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

func TestVerify_MissingTrustedOrigin_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("not-a-jwt-token-value-1234567890"),
		Redacted:   "not-****7890",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "trusted Auth0 tenant origin")
}

func TestVerify_UntrustedIssuerClaimCannotSelectDestination(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		t.Fatalf("untrusted JWT issuer triggered request to %s", r.URL)
	}))
	defer server.Close()

	v := &Verifier{httpClient: server.Client()}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(makeJWT(server.URL + "/")),
		Redacted:   "eyJh****ture",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusUnverified, result.Status)
	assert.False(t, called)
}

func TestNewForTrustedInstance_ValidatesOrigin(t *testing.T) {
	configured, err := NewForTrustedInstance("https://fixture.eu.auth0.com/")
	require.NoError(t, err)
	assert.Equal(t, "https://fixture.eu.auth0.com", configured.apiURL)

	for _, origin := range []string{
		"http://fixture.auth0.com", "https://127.0.0.1", "https://localhost",
		"https://user:pass@fixture.auth0.com", "https://fixture.auth0.com/path",
	} {
		_, err := NewForTrustedInstance(origin)
		assert.Error(t, err, origin)
	}
}

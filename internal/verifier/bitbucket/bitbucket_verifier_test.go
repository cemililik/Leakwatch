package bitbucket

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
	bitbucketdetector "github.com/HodeTech/leakwatch/internal/detector/bitbucket"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_RealDetectorOutput_UsesPairedUsername(t *testing.T) {
	fixture := testutil.RegisteredDetectorFixtures()[detectorID]
	findings := testutil.ScanViaMatcher(&bitbucketdetector.Detector{}, fixture)
	require.Len(t, findings, 1)
	require.Equal(t, "fixture-user", findings[0].ExtraData["username"])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, findings[0].ExtraData["username"], username)
		assert.Equal(t, string(findings[0].Raw), password)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"display_name":"Fixture User"}`))
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(t.Context(), findings[0])
	require.Equal(t, finding.StatusVerifiedActive, result.Status)
}

func TestVerify_ValidPassword_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/2.0/user", r.URL.Path)

		// Verify Basic auth: username + app password.
		auth := r.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(auth, "Basic "))
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		require.NoError(t, err)
		parts := strings.SplitN(string(decoded), ":", 2)
		assert.Equal(t, "jdoe", parts[0])
		assert.Equal(t, "ATBBabcdef1234567890abcdef123456", parts[1])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"display_name":"John Doe","username":"jdoe"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("ATBBabcdef1234567890abcdef123456"),
		Redacted:   "ATBB****3456",
		ExtraData:  map[string]string{"username": "jdoe"},
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Bitbucket app password is active", result.Message)
	assert.Equal(t, "John Doe", result.ExtraData["display_name"])
}

func TestVerify_InvalidPassword_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Invalid credentials"}}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("ATBBinvalidpassword12345678901234"),
		Redacted:   "ATBB****1234",
		ExtraData:  map[string]string{"username": "jdoe"},
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Bitbucket app password is invalid or revoked", result.Message)
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
		Raw:        []byte("ATBBsomepassword123456789012abcd"),
		Redacted:   "ATBB****abcd",
		ExtraData:  map[string]string{"username": "jdoe"},
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "bitbucket-app-password", v.Type())
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

func TestVerify_NoUsername_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("ATBBabcdef1234567890abcdef123456"),
		Redacted:   "ATBB****3456",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "Bitbucket username required", result.Message)
}

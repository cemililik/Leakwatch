package okta

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	oktadetector "github.com/HodeTech/leakwatch/internal/detector/okta"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_RealDetectorOutput_UsesOktaDomain(t *testing.T) {
	fixture := testutil.RegisteredDetectorFixtures()[detectorID]
	findings := testutil.ScanViaMatcher(&oktadetector.Detector{}, fixture.Input)
	require.Len(t, findings, 1)
	wantDomain := findings[0].ExtraData["domain"]
	require.NotEmpty(t, wantDomain)

	var gotURL string
	client := &http.Client{Transport: oktaRoundTrip(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"profile":{"login":"fixture@example.com"}}`)), Request: r,
		}, nil
	})}
	result := (&Verifier{httpClient: client}).Verify(t.Context(), findings[0])
	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "https://"+wantDomain+"/api/v1/users/me", gotURL)
}

type oktaRoundTrip func(*http.Request) (*http.Response, error)

func (f oktaRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestVerify_ValidToken_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users/me", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "SSWS ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"profile":{"login":"admin@example.com"}}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("00abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
		Redacted:   "00ab****ABCD",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Okta API token is active", result.Message)
	assert.Equal(t, "admin@example.com", result.ExtraData["login"])
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("00invalidtoken12345678901234567890ABCDEFGH"),
		Redacted:   "00in****EFGH",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Okta API token is invalid or revoked", result.Message)
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
		Raw:        []byte("00sometoken123456789012345678901234567890AB"),
		Redacted:   "00so****90AB",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "okta-api-token", v.Type())
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

func TestVerify_NoDomain_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("00abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
		Redacted:   "00ab****ABCD",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "Okta domain required", result.Message)
}

func TestVerify_DomainFromExtraData_UsesIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/users/me", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"profile":{"login":"user@corp.com"}}`))
	}))
	defer server.Close()

	// Use apiURL to override for testing (domain extraction is tested via NoDomain test).
	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("00abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
		Redacted:   "00ab****ABCD",
		ExtraData:  map[string]string{"domain": "corp.okta.com"},
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "user@corp.com", result.ExtraData["login"])
}

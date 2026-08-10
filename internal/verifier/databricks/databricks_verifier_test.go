package databricks

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
	databricksdetector "github.com/HodeTech/leakwatch/internal/detector/databricks"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_RealDetectorOutput_UsesWorkspaceHost(t *testing.T) {
	fixture := testutil.RegisteredDetectorFixtures()[detectorID]
	findings := testutil.ScanViaMatcher(&databricksdetector.Detector{}, fixture)
	require.Len(t, findings, 1)
	wantOrigin := findings[0].ExtraData["host"]
	require.NotEmpty(t, wantOrigin)

	var gotURL string
	client := &http.Client{Transport: databricksRoundTrip(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"userName":"fixture@example.com"}`)), Request: r,
		}, nil
	})}
	result := (&Verifier{httpClient: client}).Verify(t.Context(), findings[0])
	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, wantOrigin+"/api/2.0/preview/scim/v2/Me", gotURL)
}

type databricksRoundTrip func(*http.Request) (*http.Response, error)

func (f databricksRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestVerify_ValidToken_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/2.0/preview/scim/v2/Me", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"userName":"user@example.com"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("dapi1234567890abcdef1234567890abcdef"),
		Redacted:   "dapi****cdef",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Databricks token is active", result.Message)
	assert.Equal(t, "user@example.com", result.ExtraData["userName"])
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("dapi-invalidtoken123456789012345678"),
		Redacted:   "dapi****5678",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Databricks token is invalid or revoked", result.Message)
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("dapi-sometoken1234567890123456789012"),
		Redacted:   "dapi****9012",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_HostFromExtraData_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/2.0/preview/scim/v2/Me", r.URL.Path)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"userName":"user@example.com"}`))
	}))
	defer server.Close()

	// No apiURL override: the workspace host must be taken from ExtraData.
	v := &Verifier{
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("dapi1234567890abcdef1234567890abcdef"),
		Redacted:   "dapi****cdef",
		ExtraData:  map[string]string{"host": server.URL + "/"},
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "user@example.com", result.ExtraData["userName"])
}

func TestVerify_NoWorkspaceHost_ReturnsUnverified(t *testing.T) {
	// No apiURL override and no ExtraData host: the verifier must not guess a
	// host; it returns an indeterminate (format-only) result.
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("dapi1234567890abcdef1234567890abcdef"),
		Redacted:   "dapi****cdef",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "workspace host required")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "databricks-token", v.Type())
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

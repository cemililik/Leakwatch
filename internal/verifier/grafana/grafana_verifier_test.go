package grafana

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
		assert.Equal(t, permissionsPath, r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer ")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL + "/",
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678"),
		Redacted:   "glsa_****5678",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Grafana API key is active", result.Message)
}

func TestVerify_InvalidKey_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glsa_invalidkey123456789012345678901234"),
		Redacted:   "glsa_****1234",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "Grafana API key is invalid or revoked", result.Message)
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
		Raw:        []byte("glsa_somekey12345678901234567890123456"),
		Redacted:   "glsa_****3456",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_ForbiddenIsNotInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	v := &Verifier{apiURL: server.URL, httpClient: server.Client()}
	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glsa_permissionlimited12345678901234567890_12345678"),
		Redacted:   "glsa_****5678",
	}

	result := v.Verify(context.Background(), raw)
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "403")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "grafana-api-key", v.Type())
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

func TestVerify_NoTrustedInstance_ReturnsUnverifiedWithoutRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	for _, field := range []string{"instance_url", "grafana_url", "url", "domain"} {
		t.Run(field, func(t *testing.T) {
			v := &Verifier{httpClient: server.Client()}
			raw := detector.RawFinding{
				DetectorID: detectorID,
				Raw:        []byte("glsa_repositorycontrolled123456789012345_12345678"),
				Redacted:   "glsa_****5678",
				ExtraData:  map[string]string{field: server.URL},
			}

			result := v.Verify(context.Background(), raw)
			assert.Equal(t, finding.StatusUnverified, result.Status)
			assert.Equal(t, "Grafana instance URL required", result.Message)
		})
	}
	assert.Zero(t, requests, "repository-provided URLs must never become verifier targets")
}

func TestVerify_CentralPortalHintCannotProduceInactive(t *testing.T) {
	v := &Verifier{}
	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glsa_centralportalfixture123456789012345_12345678"),
		Redacted:   "glsa_****5678",
		ExtraData:  map[string]string{"instance_url": "https://grafana.com"},
	}

	result := v.Verify(context.Background(), raw)
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.NotEqual(t, finding.StatusVerifiedInactive, result.Status)
}

func TestVerify_RedirectIsNotFollowedOrInactive(t *testing.T) {
	targetRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer target.Close()

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer issuer.Close()
	client := issuer.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	v := &Verifier{apiURL: issuer.URL, httpClient: client}
	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glsa_redirectfixture123456789012345678901_12345678"),
		Redacted:   "glsa_****5678",
	}
	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Zero(t, targetRequests)
}

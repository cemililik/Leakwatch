package grafana

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "Bearer glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678", r.Header.Get("Authorization"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	v := &Verifier{
		instanceURL: strings.TrimRight(server.URL, "/"),
		httpClient:  server.Client(),
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
		instanceURL: server.URL,
		httpClient:  server.Client(),
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
		instanceURL: server.URL,
		httpClient:  server.Client(),
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

	v := &Verifier{instanceURL: server.URL, httpClient: server.Client()}
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

func TestVerify_WhitespaceToken_ReturnsUnverifiedWithoutRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	v := &Verifier{instanceURL: server.URL, httpClient: server.Client()}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte(" \t\r\n")})

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
	assert.Zero(t, requests)
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
	v := &Verifier{instanceURL: issuer.URL}
	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glsa_redirectfixture123456789012345678901_12345678"),
		Redacted:   "glsa_****5678",
	}
	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Zero(t, targetRequests)
}

func TestVerify_InvalidSuccessBodiesAreNotActive(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "HTML login page", contentType: "text/html", body: "<html>Sign in</html>"},
		{name: "malformed JSON", contentType: "application/json", body: `{not-json`},
		{name: "null", contentType: "application/json", body: `null`},
		{name: "array", contentType: "application/json", body: `[]`},
		{name: "scalar", contentType: "application/json", body: `true`},
		{name: "trailing value", contentType: "application/json", body: `{} {}`},
		{name: "truncated oversized object", contentType: "application/json", body: `{"permission":"` + strings.Repeat("x", 1<<20) + `"}`},
		{name: "oversized trailing whitespace", contentType: "application/json", body: `{}` + strings.Repeat(" ", (1<<20)+1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			v := &Verifier{instanceURL: server.URL, httpClient: server.Client()}
			result := v.Verify(context.Background(), detector.RawFinding{
				Raw:      []byte("glsa_invalidbodyfixture12345678901234567_12345678"),
				Redacted: "glsa_****5678",
			})

			assert.Equal(t, finding.StatusVerifyError, result.Status)
			assert.NotEqual(t, finding.StatusVerifiedActive, result.Status)
		})
	}
}

func TestNewForTrustedInstance_Validation(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "Grafana Cloud stack", url: " https://example.grafana.net/ ", want: "https://example.grafana.net"},
		{name: "self hosted origin", url: "https://grafana.example.test:8443", want: "https://grafana.example.test:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewForTrustedInstance(tc.url)
			require.NoError(t, err)
			assert.Equal(t, tc.want, v.instanceURL)
		})
	}

	invalid := []string{
		"", "grafana.example.test", "http://grafana.example.test",
		"https://user:pass@grafana.example.test", "https://grafana.example.test/path",
		"https://grafana.example.test?next=x", "https://grafana.example.test#fragment",
		"https://grafana.com", "https://www.grafana.com/", "https://localhost",
		"https://grafana.localhost", "https://127.0.0.1", "https://10.0.0.1",
		"https://169.254.169.254", "https://[::1]", "https://*.grafana.net",
	}
	for i, rawURL := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", i), func(t *testing.T) {
			v, err := NewForTrustedInstance(rawURL)
			require.Error(t, err)
			assert.Nil(t, v)
		})
	}
}

package gitlab

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
		assert.NotEmpty(t, r.Header.Get("PRIVATE-TOKEN"))

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/user":
			_, _ = w.Write([]byte(`{"id":1,"username":"johndoe","name":"John Doe"}`))
		case "/api/v4/personal_access_tokens/self":
			_, _ = w.Write([]byte(`{"active":true,"revoked":false,"scopes":["read_api","api","api"],"expires_at":"2027-02-03"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab"),
		Redacted:   "glpat-****YZab",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "GitLab token is active", result.Message)
	assert.Equal(t, "johndoe", result.ExtraData["username"])
	assert.Equal(t, "api,read_api", result.ExtraData["scopes"])
	assert.Equal(t, "2", result.ExtraData["scope_count"])
	assert.Equal(t, "2027-02-03", result.ExtraData["expires_at"])
}

func TestVerifyWithRequestGate_MetadataFailureDoesNotEraseProvenActiveIdentity(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v4/user" {
			_, _ = w.Write([]byte(`{"id":1,"username":"johndoe"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"404 Not Found"}`))
	}))
	defer server.Close()

	admissions := 0
	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).VerifyWithRequestGate(
		context.Background(),
		detector.RawFinding{Raw: []byte("glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab")},
		func() *finding.VerificationResult { admissions++; return nil },
	)
	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, 2, requests)
	assert.Equal(t, 2, admissions)
}

func TestVerifyWithRequestGate_RejectionPreventsAnyRequest(t *testing.T) {
	called := false
	v := &Verifier{apiURL: "https://trusted.example", httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, assert.AnError
	})}}
	rejection := finding.VerificationResult{Status: finding.StatusVerifyError, Message: "admission rejected"}
	result := v.VerifyWithRequestGate(context.Background(), detector.RawFinding{
		Raw: []byte("glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab"),
	}, func() *finding.VerificationResult { return &rejection })
	assert.Equal(t, rejection, result)
	assert.False(t, called)
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glpat-invalidtoken12345678901234567"),
		Redacted:   "glpat-****4567",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, "GitLab token is invalid or revoked", result.Message)
}

func TestVerify_DPoPChallengeDoesNotProveTokenInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"DPoP proof required"}`))
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
		context.Background(),
		detector.RawFinding{DetectorID: detectorID, Raw: []byte("glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab")},
	)
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.NotContains(t, result.Message, "DPoP")
}

func TestVerify_ActiveResponseRequiresCompleteJSONIdentity(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "empty object", contentType: "application/json", body: `{}`},
		{name: "null", contentType: "application/json", body: `null`},
		{name: "missing username", contentType: "application/json", body: `{"id":1}`},
		{name: "missing id", contentType: "application/json", body: `{"username":"johndoe"}`},
		{name: "trailing json", contentType: "application/json", body: `{"id":1,"username":"johndoe"}{}`},
		{name: "wrong content type", contentType: "text/html", body: `{"id":1,"username":"johndoe"}`},
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
				context.Background(),
				detector.RawFinding{DetectorID: detectorID, Raw: []byte("glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab")},
			)
			assert.Equal(t, finding.StatusVerifyError, result.Status)
		})
	}
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"500 Internal server error"}`))
	}))
	defer server.Close()

	v := &Verifier{
		apiURL:     server.URL,
		httpClient: server.Client(),
	}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glpat-sometoken123456789012345678901"),
		Redacted:   "glpat-****8901",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "gitlab-pat", v.Type())
}

func TestVerify_RepositoryHostNeverSelectsDestination(t *testing.T) {
	called := false
	v := &Verifier{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, assert.AnError
	})}}
	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glpat-selfhostedtoken123456789012"),
		ExtraData:  map[string]string{"host": "gitlab.attacker.example"},
	}
	result := v.Verify(context.Background(), raw)
	require.Equal(t, finding.StatusUnverified, result.Status)
	assert.False(t, called)
}

func TestVerify_NonPATSubtypesRemainUnverified(t *testing.T) {
	for _, prefix := range []string{
		"gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glimt-", "glagent-",
		"glwt-", "glsoat-", "glffct-", "gloas-", "glft-",
	} {
		result := (&Verifier{apiURL: "https://trusted.example"}).Verify(context.Background(), detector.RawFinding{
			DetectorID: detectorID, Raw: []byte(prefix + "abcDEF1234567890xyzW"),
		})
		assert.Equal(t, finding.StatusUnverified, result.Status, prefix)
	}
}

func TestNewForTrustedInstance_ValidatesOrigin(t *testing.T) {
	configured, err := NewForTrustedInstance("https://gitlab.example.com/")
	require.NoError(t, err)
	assert.Equal(t, "https://gitlab.example.com", configured.apiURL)
	for _, origin := range []string{"http://gitlab.com", "https://127.0.0.1", "https://localhost", "https://gitlab.com/path"} {
		_, err := NewForTrustedInstance(origin)
		assert.Error(t, err, origin)
	}
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

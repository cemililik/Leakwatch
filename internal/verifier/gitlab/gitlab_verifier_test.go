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
		assert.Equal(t, "/api/v4/user", r.URL.Path)
		assert.NotEmpty(t, r.Header.Get("PRIVATE-TOKEN"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"username":"johndoe","name":"John Doe"}`))
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
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestBaseURL_DerivesHostFromExtraData(t *testing.T) {
	tests := []struct {
		name   string
		apiURL string
		extra  map[string]string
		want   string
	}{
		{
			name: "no context defaults to gitlab.com",
			want: "https://gitlab.com",
		},
		{
			name:  "self-hosted host from ExtraData",
			extra: map[string]string{"host": "gitlab.example.com"},
			want:  "https://gitlab.example.com",
		},
		{
			name:  "self-hosted host with port",
			extra: map[string]string{"host": "gitlab.corp.internal:8443"},
			want:  "https://gitlab.corp.internal:8443",
		},
		{
			name:   "apiURL override wins",
			apiURL: "http://127.0.0.1:1234",
			extra:  map[string]string{"host": "gitlab.example.com"},
			want:   "http://127.0.0.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{apiURL: tt.apiURL}
			raw := detector.RawFinding{DetectorID: detectorID, ExtraData: tt.extra}
			assert.Equal(t, tt.want, v.baseURL(raw))
		})
	}
}

func TestVerify_SelfHostedActiveToken_NotReportedInvalid(t *testing.T) {
	// A live self-hosted token verified against its true issuer must read as
	// active, never as "invalid or revoked". The test server stands in for the
	// self-hosted instance the detector captured into ExtraData["host"].
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/user", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"username":"selfhosted-user"}`))
	}))
	defer server.Close()

	v := &Verifier{apiURL: server.URL, httpClient: server.Client()}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("glpat-selfhostedtoken123456789012"),
		Redacted:   "glpat-****9012",
		ExtraData:  map[string]string{"host": "gitlab.example.com"},
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "selfhosted-user", result.ExtraData["username"])
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

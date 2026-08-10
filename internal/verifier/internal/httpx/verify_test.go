package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

const testToken = "test-token-1234567890"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// jsonServer returns a test server that responds with the given status code and
// body, asserting nothing about the request.
func jsonServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestVerifyToken_EmptyToken_ReturnsUnverified(t *testing.T) {
	res := VerifyToken(context.Background(), nil, "", TokenSpec{
		Name:    "x",
		Request: Request{URL: "http://127.0.0.1:0/never"},
	})
	assert.Equal(t, finding.StatusUnverified, res.Status)
	assert.Equal(t, "empty token", res.Message)
}

func TestVerifyToken_Active_NoDecode_NoExtra(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:          "x",
		Request:       Request{URL: server.URL},
		ActiveMessage: "secret active",
	})
	assert.Equal(t, finding.StatusVerifiedActive, res.Status)
	assert.Equal(t, "secret active", res.Message)
	assert.Nil(t, res.ExtraData)
}

func TestVerifyToken_RequiredJSONContentType(t *testing.T) {
	tests := []struct {
		contentType string
		want        finding.VerificationStatus
	}{
		{contentType: "application/json", want: finding.StatusVerifiedActive},
		{contentType: "application/json; charset=utf-8", want: finding.StatusVerifiedActive},
		{contentType: "application/problem+json", want: finding.StatusVerifiedActive},
		{contentType: "text/html", want: finding.StatusVerifyError},
		{contentType: "", want: finding.StatusVerifyError},
		{contentType: "not a media type", want: finding.StatusVerifyError},
	}
	for _, tc := range tests {
		t.Run(tc.contentType, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer server.Close()

			result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
				Name:                   "x",
				Request:                Request{URL: server.URL},
				ActiveMessage:          "active",
				RequireJSONContentType: true,
			})
			assert.Equal(t, tc.want, result.Status)
		})
	}
}

func TestVerifyToken_Active_NoDecode_WithActiveExtra(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:          "x",
		Request:       Request{URL: server.URL},
		ActiveMessage: "secret active",
		ActiveExtra:   map[string]string{"key_type": "live"},
	})
	assert.Equal(t, finding.StatusVerifiedActive, res.Status)
	assert.Equal(t, "live", res.ExtraData["key_type"])
}

func TestVerifyToken_Active_Decode_PopulatesExtra(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{"name":"alice"}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:          "x",
		Request:       Request{URL: server.URL},
		ActiveMessage: "secret active",
		Decode: func(body io.Reader) (map[string]string, string, error) {
			var v struct {
				Name string `json:"name"`
			}
			if err := decodeJSON(body, &v); err != nil {
				return nil, "", err
			}
			return map[string]string{"name": v.Name}, "", nil
		},
	})
	assert.Equal(t, finding.StatusVerifiedActive, res.Status)
	assert.Equal(t, "alice", res.ExtraData["name"])
}

func TestVerifyToken_Decode_DowngradesToInactive(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{"ok":false}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:          "x",
		Request:       Request{URL: server.URL},
		ActiveMessage: "secret active",
		Decode: func(io.Reader) (map[string]string, string, error) {
			return nil, "downgraded by body", nil
		},
	})
	assert.Equal(t, finding.StatusVerifiedInactive, res.Status)
	assert.Equal(t, "downgraded by body", res.Message)
}

func TestVerifyToken_Decode_ErrorIsVerifyError(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{bad json`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:          "x",
		Request:       Request{URL: server.URL},
		ActiveMessage: "secret active",
		Decode: func(io.Reader) (map[string]string, string, error) {
			return nil, "", errors.New("boom")
		},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "failed to decode response body")
}

func TestVerifyToken_Inactive_Default401(t *testing.T) {
	server := jsonServer(t, http.StatusUnauthorized, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:            "x",
		Request:         Request{URL: server.URL},
		InactiveMessage: "secret revoked",
	})
	assert.Equal(t, finding.StatusVerifiedInactive, res.Status)
	assert.Equal(t, "secret revoked", res.Message)
}

func TestVerifyToken_Inactive_CustomStatus403(t *testing.T) {
	server := jsonServer(t, http.StatusForbidden, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:             "x",
		Request:          Request{URL: server.URL},
		InactiveStatuses: []int{http.StatusForbidden},
		InactiveMessage:  "secret revoked",
	})
	assert.Equal(t, finding.StatusVerifiedInactive, res.Status)
}

func TestVerifyToken_CustomActiveStatus405(t *testing.T) {
	server := jsonServer(t, http.StatusMethodNotAllowed, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:             "x",
		Request:          Request{URL: server.URL},
		ActiveStatuses:   []int{http.StatusMethodNotAllowed},
		InactiveStatuses: []int{http.StatusUnauthorized, http.StatusForbidden},
		ActiveMessage:    "secret active",
	})
	assert.Equal(t, finding.StatusVerifiedActive, res.Status)
}

func TestVerifyToken_EmptyInactiveStatuses_401IsUnexpected(t *testing.T) {
	server := jsonServer(t, http.StatusUnauthorized, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:             "x",
		Request:          Request{URL: server.URL},
		InactiveStatuses: []int{},
		ActiveMessage:    "secret active",
		Decode: func(io.Reader) (map[string]string, string, error) {
			return nil, "", nil
		},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "401")
}

func TestVerifyToken_UnexpectedStatus(t *testing.T) {
	server := jsonServer(t, http.StatusInternalServerError, `{}`)
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:    "x",
		Request: Request{URL: server.URL},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "500")
}

func TestVerifyToken_RateLimited_429IsDistinguished(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:    "x",
		Request: Request{URL: server.URL},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "rate limited by provider")
	assert.Contains(t, res.Message, "Retry-After: 30")
	// A rate-limit response must be actionable, not the generic unexpected-status
	// message.
	assert.NotContains(t, res.Message, "unexpected status code")
}

func TestRateLimited(t *testing.T) {
	withHeader := RateLimited(context.Background(), "x", "12")
	assert.Equal(t, finding.StatusVerifyError, withHeader.Status)
	assert.Contains(t, withHeader.Message, "Retry-After: 12")

	noHeader := RateLimited(context.Background(), "x", "")
	assert.Equal(t, finding.StatusVerifyError, noHeader.Status)
	assert.Contains(t, noHeader.Message, "rate limited by provider")
	assert.NotContains(t, noHeader.Message, "Retry-After")
}

func TestRateLimited_DoesNotReflectArbitraryHeaderText(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	result := RateLimited(context.Background(), "x", testToken)
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.NotContains(t, result.Message, testToken)
	assert.NotContains(t, logs.String(), testToken)
	assert.NotContains(t, result.Message, "Retry-After")

	httpDate := "Wed, 21 Oct 2015 07:28:00 GMT"
	result = RateLimited(context.Background(), "x", httpDate)
	assert.Contains(t, result.Message, "Retry-After: "+httpDate)

	result = RateLimited(context.Background(), "x", " 00030 ")
	assert.Contains(t, result.Message, "Retry-After: 30")
}

func TestVerifyToken_Redirect_IsVerifyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://example.com/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	// A nil client exercises the shared hardened (no-redirect) Client.
	res := VerifyToken(context.Background(), nil, testToken, TokenSpec{
		Name:    "x",
		Request: Request{URL: server.URL},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "unexpected redirect")
}

func TestVerifyToken_TransportError_RedactsSecretInURL(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{}`)
	url := server.URL
	client := server.Client()
	server.Close() // Force a connection-refused transport error.

	res := VerifyToken(context.Background(), client, testToken, TokenSpec{
		Name:    "x",
		Request: Request{URL: url + "/" + testToken},
		Redact:  testToken,
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.NotContains(t, res.Message, testToken)
	assert.Contains(t, res.Message, "[REDACTED]")
}

func TestVerifyToken_TransportError_AlwaysRedactsTokenArgument(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("proxy echoed header credential %s", testToken)
	})}

	res := VerifyToken(context.Background(), client, testToken, TokenSpec{
		Name:    "x",
		Request: Request{URL: "https://api.example.invalid"},
	})
	require.Equal(t, finding.StatusVerifyError, res.Status)
	assert.NotContains(t, res.Message, testToken)
	assert.Contains(t, res.Message, "[REDACTED]")
	assert.NotContains(t, logs.String(), testToken)
}

func TestVerifyToken_BasicAuthAndHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "api", user)
		assert.Equal(t, testToken, pass)
		assert.Equal(t, "custom", r.Header.Get("X-Test"))
		assert.Equal(t, userAgent, r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name: "x",
		Request: Request{
			URL:           server.URL,
			Header:        map[string]string{"X-Test": "custom"},
			BasicAuthUser: "api",
			BasicAuthPass: testToken,
		},
		ActiveMessage: "secret active",
	})
	assert.Equal(t, finding.StatusVerifiedActive, res.Status)
}

func TestVerifyToken_PostBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		got, _ := io.ReadAll(r.Body)
		assert.Equal(t, `{"q":1}`, string(got))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name: "x",
		Request: Request{
			Method: http.MethodPost,
			URL:    server.URL,
			Body:   []byte(`{"q":1}`),
		},
		ActiveMessage: "secret active",
	})
	assert.Equal(t, finding.StatusVerifiedActive, res.Status)
}

func TestVerifyToken_RequestBuildError(t *testing.T) {
	res := VerifyToken(context.Background(), nil, testToken, TokenSpec{
		Name:    "x",
		Request: Request{Method: "in valid method", URL: "http://127.0.0.1:0/"},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "failed to create request")
}

func TestBaseURL(t *testing.T) {
	assert.Equal(t, "https://fallback", BaseURL("", "https://fallback"))
	assert.Equal(t, "https://override", BaseURL("https://override", "https://fallback"))
}

func TestUnexpectedStatus(t *testing.T) {
	res := UnexpectedStatus(context.Background(), "x", http.StatusTeapot)
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "418")
}

// decodeJSON mirrors how real verifiers decode a bounded response body.
func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

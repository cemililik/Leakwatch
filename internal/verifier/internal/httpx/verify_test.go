package httpx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

const testToken = "test-token-1234567890"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type closeTrackingBody struct {
	io.Reader
	closed *atomic.Bool
}

func (b *closeTrackingBody) Close() error {
	b.closed.Store(true)
	return nil
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

func TestVerifyToken_ResponseDecoderReceivesHeadersAndBoundedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Safe-Metadata", "scope-a")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:    "header-aware",
		Request: Request{URL: server.URL},
		DecodeResponse: func(header http.Header, body io.Reader) (map[string]string, string, error) {
			contents, err := io.ReadAll(body)
			require.NoError(t, err)
			assert.JSONEq(t, `{"ok":true}`, string(contents))
			return map[string]string{"scope": header.Get("X-Safe-Metadata")}, "", nil
		},
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "scope-a", result.ExtraData["scope"])
}

func TestVerifyToken_RejectsMultipleActiveDecoders(t *testing.T) {
	server := jsonServer(t, http.StatusOK, `{}`)
	defer server.Close()

	decode := func(io.Reader) (map[string]string, string, error) { return nil, "", nil }
	result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:           "invalid-contract",
		Request:        Request{URL: server.URL},
		Decode:         decode,
		DecodeResponse: func(http.Header, io.Reader) (map[string]string, string, error) { return nil, "", nil },
	})
	assert.Equal(t, finding.StatusVerifyError, result.Status)
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

func TestVerifyToken_InactiveRequiresDefinitiveBodyWhenConfigured(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		decodeErr   error
		want        finding.VerificationStatus
	}{
		{name: "definitive json", contentType: "application/json", body: `{"message":"revoked"}`, want: finding.StatusVerifiedInactive},
		{name: "ambiguous json", contentType: "application/json", body: `{"error":"challenge"}`, decodeErr: errors.New("not definitive"), want: finding.StatusVerifyError},
		{name: "wrong content type", contentType: "text/html", body: `{"message":"revoked"}`, want: finding.StatusVerifyError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			res := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
				Name:                   "x",
				Request:                Request{URL: server.URL},
				InactiveMessage:        "secret revoked",
				RequireJSONContentType: true,
				DecodeInactive: func(io.Reader) error {
					return tc.decodeErr
				},
			})
			assert.Equal(t, tc.want, res.Status)
		})
	}
}

func TestVerifyToken_InactiveRequiresJSONWithoutDecoder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html>proxy login</html>`))
	}))
	defer server.Close()

	result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:                   "x",
		Request:                Request{URL: server.URL},
		InactiveMessage:        "secret revoked",
		RequireJSONContentType: true,
	})
	assert.Equal(t, finding.StatusVerifyError, result.Status)
}

func TestVerifyToken_InactiveBodyIsBounded(t *testing.T) {
	server := jsonServer(t, http.StatusUnauthorized, strings.Repeat("x", int(MaxBodyBytes)+1))
	defer server.Close()

	result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:                   "x",
		Request:                Request{URL: server.URL},
		RequireJSONContentType: true,
		DecodeInactive: func(io.Reader) error {
			t.Fatal("oversized inactive body must not reach the decoder")
			return nil
		},
	})
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "exceeds")
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
		Name: "x",
		// POST is deliberately not retried: the shared helper only retries safe
		// GET/HEAD probes.
		Request: Request{Method: http.MethodPost, URL: server.URL},
	})
	assert.Equal(t, finding.StatusVerifyError, res.Status)
	assert.Contains(t, res.Message, "rate limited by provider")
	assert.Contains(t, res.Message, "Retry-After: 30")
	// A rate-limit response must be actionable, not the generic unexpected-status
	// message.
	assert.NotContains(t, res.Message, "unexpected status code")
}

func TestVerifyToken_RateLimitedGETRetriesOnceAndSucceeds(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:          "x",
		Request:       Request{URL: server.URL},
		ActiveMessage: "active after retry",
	})
	assert.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, int64(2), calls.Load())
	assert.Contains(t, logs.String(), "max_attempts=2")
	assert.Contains(t, logs.String(), "max_total_wait=2s")
	assert.NotContains(t, logs.String(), testToken)
}

func TestVerifyToken_RateLimitedGETHasStrictAttemptBound(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
		Name:    "x",
		Request: Request{URL: server.URL},
	})
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "rate limited")
	assert.Equal(t, int64(max429Attempts), calls.Load())
}

func TestVerifyToken_RateLimitedDoesNotRetryUnsafeOrUnscheduledRequests(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		retryAfter string
	}{
		{name: "unsafe post", method: http.MethodPost, retryAfter: "0"},
		{name: "missing Retry-After", method: http.MethodGet},
		{name: "invalid Retry-After", method: http.MethodGet, retryAfter: "not-a-delay"},
		{name: "wait exceeds bound", method: http.MethodGet, retryAfter: "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()

			result := VerifyToken(context.Background(), server.Client(), testToken, TokenSpec{
				Name:    "x",
				Request: Request{Method: tc.method, URL: server.URL},
			})
			assert.Equal(t, finding.StatusVerifyError, result.Status)
			assert.Equal(t, int64(1), calls.Load())
		})
	}
}

func TestVerifyToken_RetryDeadlineAndAdmissionGate(t *testing.T) {
	t.Run("request gate admits every actual send", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		gateCalls := 0
		ctx := WithRequestGate(context.Background(), func() *finding.VerificationResult {
			gateCalls++
			return nil
		})
		result := VerifyToken(ctx, server.Client(), testToken, TokenSpec{Name: "x", Request: Request{URL: server.URL}})
		assert.Equal(t, finding.StatusVerifiedActive, result.Status)
		assert.Equal(t, int64(2), calls.Load())
		assert.Equal(t, 2, gateCalls)
	})

	t.Run("request gate rejection prevents initial transport", func(t *testing.T) {
		var calls atomic.Int64
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, errors.New("transport must not run")
		})}
		ctx := WithRequestGate(context.Background(), func() *finding.VerificationResult {
			return &finding.VerificationResult{Status: finding.StatusVerifyError, Message: "admission rejected"}
		})

		result := VerifyToken(ctx, client, testToken, TokenSpec{
			Name:    "x",
			Request: Request{URL: "https://provider.example.test/probe"},
		})
		assert.Equal(t, finding.StatusVerifyError, result.Status)
		assert.Equal(t, "admission rejected", result.Message)
		assert.Zero(t, calls.Load())
	})

	t.Run("empty token consumes no request admission", func(t *testing.T) {
		gateCalls := 0
		ctx := WithRequestGate(context.Background(), func() *finding.VerificationResult {
			gateCalls++
			return nil
		})
		result := VerifyToken(ctx, nil, "", TokenSpec{Name: "x", Request: Request{URL: "https://provider.example.test"}})
		assert.Equal(t, finding.StatusUnverified, result.Status)
		assert.Zero(t, gateCalls)
	})

	t.Run("deadline too short prevents wait and request", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		started := time.Now()
		result := VerifyToken(ctx, server.Client(), testToken, TokenSpec{Name: "x", Request: Request{URL: server.URL}})
		assert.Equal(t, finding.StatusVerifyError, result.Status)
		assert.Equal(t, int64(1), calls.Load())
		assert.Less(t, time.Since(started), 200*time.Millisecond)
	})

	t.Run("gate rejection prevents retry request", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()

		gateCalls := 0
		ctx := WithRetryGate(context.Background(), func() *finding.VerificationResult {
			gateCalls++
			return &finding.VerificationResult{Status: finding.StatusVerifyError, Message: "admission rejected"}
		})
		result := VerifyToken(ctx, server.Client(), testToken, TokenSpec{Name: "x", Request: Request{URL: server.URL}})
		assert.Equal(t, finding.StatusVerifyError, result.Status)
		assert.Equal(t, "admission rejected", result.Message)
		assert.Equal(t, 1, gateCalls)
		assert.Equal(t, int64(1), calls.Load())
	})
}

func TestAddRetryJitter_IsBoundedAndNeverShortensRetryAfter(t *testing.T) {
	base := time.Second
	assert.Equal(t, base, addRetryJitter(base, max429RetryWait, 0))
	assert.Equal(t, 1100*time.Millisecond, addRetryJitter(base, max429RetryWait, 1))
	assert.Equal(t, max429RetryWait, addRetryJitter(1950*time.Millisecond, max429RetryWait, 1))
	for range 100 {
		unit := retryJitterUnit()
		assert.GreaterOrEqual(t, unit, float64(0))
		assert.LessOrEqual(t, unit, float64(1))
	}
}

func TestVerifyToken_RetryAndDecodePanicAlwaysCloseResponseBodies(t *testing.T) {
	t.Run("redirect drains and closes response", func(t *testing.T) {
		var closed atomic.Bool
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     make(http.Header),
				Body:       &closeTrackingBody{Reader: strings.NewReader("redirect body"), closed: &closed},
			}, nil
		})}

		result := VerifyToken(context.Background(), client, testToken, TokenSpec{
			Name:    "x",
			Request: Request{URL: "https://provider.example.test/probe"},
		})
		assert.Equal(t, finding.StatusVerifyError, result.Status)
		assert.Contains(t, result.Message, "redirect")
		assert.True(t, closed.Load())
	})

	t.Run("retry closes the 429 response before the next request", func(t *testing.T) {
		var (
			calls       atomic.Int64
			firstClosed atomic.Bool
			lastClosed  atomic.Bool
		)
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     http.Header{"Retry-After": []string{"0"}},
					Body:       &closeTrackingBody{Reader: strings.NewReader("rate limited"), closed: &firstClosed},
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &closeTrackingBody{Reader: strings.NewReader("ok"), closed: &lastClosed},
			}, nil
		})}

		result := VerifyToken(context.Background(), client, testToken, TokenSpec{
			Name:          "x",
			Request:       Request{URL: "https://provider.example.test/probe"},
			ActiveMessage: "active",
		})
		assert.Equal(t, finding.StatusVerifiedActive, result.Status)
		assert.True(t, firstClosed.Load())
		assert.True(t, lastClosed.Load())
	})

	t.Run("provider decode panic still closes final response", func(t *testing.T) {
		var closed atomic.Bool
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &closeTrackingBody{Reader: strings.NewReader(`{}`), closed: &closed},
			}, nil
		})}
		assert.Panics(t, func() {
			VerifyToken(context.Background(), client, testToken, TokenSpec{
				Name:    "x",
				Request: Request{URL: "https://provider.example.test/probe"},
				Decode: func(io.Reader) (map[string]string, string, error) {
					panic("synthetic decoder panic")
				},
			})
		})
		assert.True(t, closed.Load())
	})
}

func TestRetryAfterDelay_ParsesBoundedly(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	delay, ok := retryAfterDelay("1", now)
	require.True(t, ok)
	assert.Equal(t, time.Second, delay)

	delay, ok = retryAfterDelay(now.Add(time.Second).Format(http.TimeFormat), now)
	require.True(t, ok)
	assert.Equal(t, time.Second, delay)

	delay, ok = retryAfterDelay("18446744073709551615", now)
	require.True(t, ok)
	assert.Greater(t, delay, max429RetryWait)

	_, ok = retryAfterDelay("invalid", now)
	assert.False(t, ok)
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

func TestVerifyToken_TransportError_RedactsDerivedBasicAuthorization(t *testing.T) {
	const user = "synthetic-user"
	const password = "synthetic-password-1234"
	encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("proxy echoed Authorization: Basic %s", encoded)
	})}

	res := VerifyToken(context.Background(), client, password, TokenSpec{
		Name: "x",
		Request: Request{
			URL:           "https://api.example.invalid",
			BasicAuthUser: user,
			BasicAuthPass: password,
		},
	})
	require.Equal(t, finding.StatusVerifyError, res.Status)
	assert.NotContains(t, res.Message, encoded)
	assert.NotContains(t, res.Message, password)
	assert.Contains(t, res.Message, "[REDACTED]")
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

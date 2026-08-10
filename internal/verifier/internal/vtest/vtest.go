// Package vtest provides reusable, table-driven test helpers shared by the
// secret verifier packages.
//
// It is placed under internal/verifier/internal so it can only be imported by
// verifier packages. The helpers exercise the failure paths that every HTTP
// verifier must handle safely:
//
//   - a transport error (the server is closed) must yield StatusVerifyError;
//   - a cancelled context must yield StatusVerifyError and NEVER
//     StatusVerifiedInactive (a network failure is not evidence the secret is
//     inactive);
//   - a 200 response with a malformed JSON body must yield a defined status
//     (the project standardizes this to StatusVerifyError).
package vtest

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Factory builds a verifier under test, wired to the given base URL and HTTP
// client. Both the URL and the client originate from a test server so that no
// real network call is made.
type Factory func(apiURL string, client *http.Client) verifier.Verifier

// Case configures the shared verifier suite for one verifier package.
type Case struct {
	// Name is the verifier name, used as the subtest prefix.
	Name string

	// New builds the verifier under test.
	New Factory

	// Raw is a representative finding to verify. Its Raw value should be a
	// plausibly formatted secret so the verifier reaches the HTTP call.
	Raw detector.RawFinding

	// RawForURL optionally builds the finding after the hermetic endpoint is
	// known. It is used by credentials whose request destination is the finding
	// itself, such as provider webhook URLs.
	RawForURL func(string) detector.RawFinding

	// AdditionalSensitive lists credential-bearing representations that the
	// verifier derives outside Raw/RawV2 and must redact from results and logs.
	AdditionalSensitive [][]byte

	// MalformedStatus is the status the verifier returns for a 200 response
	// whose body is not valid JSON. Defaults to StatusVerifyError when zero
	// (the project standard). Set explicitly for verifiers that only inspect
	// the status code and do not decode a body.
	MalformedStatus finding.VerificationStatus

	// SkipMalformed skips the malformed-body case for verifiers that never
	// decode a response body on success.
	SkipMalformed bool
}

// Run executes the shared safety suite against the verifier produced by c.New.
//
// It does not contact any real service: a closed httptest server is used for
// the transport-error and cancellation cases, and a live httptest server that
// returns 200 with a non-JSON body is used for the malformed-body case.
func Run(t *testing.T, c Case) {
	t.Helper()

	t.Run(c.Name+"/closed_server_returns_verify_error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			// Intentionally empty: the server is closed immediately below, so
			// this handler is never invoked. Its only purpose is to obtain a
			// valid URL/client pair that then yields a connection-refused error.
		}))
		url := server.URL
		client := server.Client()
		server.Close() // Force a connection-refused transport error.

		v := c.New(url, client)
		testCase := c.withURL(url)
		result := v.Verify(context.Background(), testCase.Raw)

		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"a transport error must be a verify error")
		assertSecretAbsent(t, result, "", testCase)
	})

	t.Run(c.Name+"/transport_error_cannot_echo_secret", func(t *testing.T) {
		var calls atomic.Int32
		const endpoint = "https://api.example.invalid"
		testCase := c.withURL(endpoint)
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, fmt.Errorf("synthetic transport failure echoed credentials %s %s",
				string(testCase.Raw.Raw), string(testCase.Raw.RawV2))
		})}
		v := c.New(endpoint, client)
		result, logs := verifyWithCapturedLogs(t, func() finding.VerificationResult {
			return v.Verify(context.Background(), testCase.Raw)
		})

		require.Equal(t, int32(1), calls.Load(), "injected transport must be exercised exactly once")
		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"a transport error must be a verify error")
		assertSecretAbsent(t, result, logs, testCase)
	})

	t.Run(c.Name+"/cancelled_context_is_not_inactive", func(t *testing.T) {
		// A server that blocks until the request context is cancelled.
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately.

		testCase := c.withURL(server.URL)
		v := c.New(server.URL, server.Client())
		result := v.Verify(ctx, testCase.Raw)

		require.NotEqual(t, finding.StatusVerifiedInactive, result.Status,
			"a cancelled context must NOT be reported as verified-inactive")
		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"a cancelled context must be a verify error")
		assertSecretAbsent(t, result, "", testCase)
	})

	if c.SkipMalformed {
		return
	}

	t.Run(c.Name+"/malformed_body_has_defined_status", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{not valid json`))
		}))
		defer server.Close()

		want := c.MalformedStatus
		if want == finding.StatusUnverified {
			// Zero value is treated as the project default for an undecodable
			// 200 body. Callers that genuinely expect Unverified should not use
			// this helper for the malformed case (set SkipMalformed instead).
			want = finding.StatusVerifyError
		}

		testCase := c.withURL(server.URL)
		v := c.New(server.URL, server.Client())
		result := v.Verify(context.Background(), testCase.Raw)

		require.Equal(t, int32(1), calls.Load(), "malformed-response transport must be exercised exactly once")
		assert.Equal(t, want, result.Status,
			"a 200 with a malformed body must have a defined status")
		assert.NotEqual(t, finding.StatusVerifiedInactive, result.Status,
			"a malformed 200 body must never be reported as verified-inactive")
		assertSecretAbsent(t, result, "", testCase)
	})
}

func (c Case) withURL(endpoint string) Case {
	if c.RawForURL != nil {
		c.Raw = c.RawForURL(endpoint)
	}
	return c
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func assertSecretAbsent(t *testing.T, result finding.VerificationResult, logs string, c Case) {
	t.Helper()
	secrets := append([][]byte{c.Raw.Raw, c.Raw.RawV2}, c.AdditionalSensitive...)
	for _, secret := range secrets {
		if len(secret) < 8 {
			continue
		}
		for _, form := range sensitiveForms(string(secret)) {
			assert.NotContains(t, result.Message, form, "verification message leaked credential")
			assert.NotContains(t, logs, form, "verification log leaked credential")
		}
		for key, value := range result.ExtraData {
			for _, form := range sensitiveForms(string(secret)) {
				assert.False(t, strings.Contains(value, form),
					"verification ExtraData[%q] leaked credential", key)
			}
		}
	}
}

func sensitiveForms(secret string) []string {
	return []string{secret, url.PathEscape(secret), url.QueryEscape(secret)}
}

var slogCaptureMu sync.Mutex

func verifyWithCapturedLogs(t *testing.T, verify func() finding.VerificationResult) (finding.VerificationResult, string) {
	t.Helper()
	slogCaptureMu.Lock()
	defer slogCaptureMu.Unlock()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	return verify(), logs.String()
}

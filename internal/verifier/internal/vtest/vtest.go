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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
		result := v.Verify(context.Background(), c.Raw)

		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"a transport error must be a verify error")
		assertSecretAbsent(t, result, c.Raw)
	})

	t.Run(c.Name+"/transport_error_cannot_echo_secret", func(t *testing.T) {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("synthetic transport failure echoed credential %s", string(c.Raw.Raw))
		})}
		v := c.New("https://api.example.invalid", client)
		result := v.Verify(context.Background(), c.Raw)

		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"a transport error must be a verify error")
		assertSecretAbsent(t, result, c.Raw)
	})

	t.Run(c.Name+"/cancelled_context_is_not_inactive", func(t *testing.T) {
		// A server that blocks until the request context is cancelled.
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately.

		v := c.New(server.URL, server.Client())
		result := v.Verify(ctx, c.Raw)

		require.NotEqual(t, finding.StatusVerifiedInactive, result.Status,
			"a cancelled context must NOT be reported as verified-inactive")
		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"a cancelled context must be a verify error")
		assertSecretAbsent(t, result, c.Raw)
	})

	if c.SkipMalformed {
		return
	}

	t.Run(c.Name+"/malformed_body_has_defined_status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

		v := c.New(server.URL, server.Client())
		result := v.Verify(context.Background(), c.Raw)

		assert.Equal(t, want, result.Status,
			"a 200 with a malformed body must have a defined status")
		assert.NotEqual(t, finding.StatusVerifiedInactive, result.Status,
			"a malformed 200 body must never be reported as verified-inactive")
		assertSecretAbsent(t, result, c.Raw)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func assertSecretAbsent(t *testing.T, result finding.VerificationResult, raw detector.RawFinding) {
	t.Helper()
	secrets := [][]byte{raw.Raw, raw.RawV2}
	for _, secret := range secrets {
		if len(secret) < 8 {
			continue
		}
		assert.NotContains(t, result.Message, string(secret), "verification message leaked raw credential")
		for key, value := range result.ExtraData {
			assert.False(t, strings.Contains(value, string(secret)),
				"verification ExtraData[%q] leaked raw credential", key)
		}
	}
}

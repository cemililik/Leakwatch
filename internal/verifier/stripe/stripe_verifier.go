// Package stripe provides verifiers for Stripe API keys (live and test).
// It uses the Stripe Balance API GET /v1/balance endpoint with Basic auth
// to check key validity.
package stripe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	liveDetectorID = "stripe-api-key-live"
	testDetectorID = "stripe-api-key-test"
)

// defaultAPIURL is the base URL for the Stripe API.
const defaultAPIURL = "https://api.stripe.com"

// LiveKeyVerifier checks whether a Stripe live API key is active by calling
// the Stripe Balance API. It NEVER logs or persists raw key values.
type LiveKeyVerifier struct {
	// apiURL overrides the Stripe API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

// TestKeyVerifier checks whether a Stripe test API key is active.
// It uses the same endpoint and logic as LiveKeyVerifier.
type TestKeyVerifier struct {
	// apiURL overrides the Stripe API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

func init() {
	verifier.Register(&LiveKeyVerifier{})
	verifier.Register(&TestKeyVerifier{})
}

// Type returns the detector ID this verifier handles.
func (v *LiveKeyVerifier) Type() string {
	return liveDetectorID
}

// Type returns the detector ID this verifier handles.
func (v *TestKeyVerifier) Type() string {
	return testDetectorID
}

// Verify checks if the detected Stripe live API key is valid/active.
func (v *LiveKeyVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return verifyStripeKey(ctx, v.apiURL, v.httpClient, raw, "live")
}

// Verify checks if the detected Stripe test API key is valid/active.
func (v *TestKeyVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return verifyStripeKey(ctx, v.apiURL, v.httpClient, raw, "test")
}

// verifyStripeKey performs the Stripe API key verification shared by both the
// live and test verifiers. Stripe authenticates the key as the Basic auth
// username (with an empty password) and reports validity by status code.
//
// The Stripe detector matches both full secret keys (sk_live_/sk_test_) and
// restricted keys (rk_live_/rk_test_) under the same detector IDs. A
// restricted key scoped without Balance-read access gets 403 from
// GET /v1/balance rather than the 200 a full key or a fully-scoped restricted
// key gets — but a 403 only happens after Stripe has authenticated the key; an
// invalid/revoked key gets 401 (the shared default InactiveStatuses), never
// 403. So 403 is treated as an active outcome distinct from a hard verify
// error: the key is live, just insufficiently scoped for this probe.
func verifyStripeKey(ctx context.Context, apiURL string, httpClient *http.Client, raw detector.RawFinding, keyType string) finding.VerificationResult {
	token := string(raw.Raw)
	resolved := httpx.BaseURL(apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, httpClient, token, httpx.TokenSpec{
		Name: "stripe",
		Request: httpx.Request{
			URL:           resolved + "/v1/balance",
			BasicAuthUser: token,
		},
		ActiveStatuses:  []int{http.StatusOK, http.StatusForbidden},
		ActiveMessage:   fmt.Sprintf("Stripe %s API key is active", keyType),
		InactiveMessage: fmt.Sprintf("Stripe %s API key is invalid or revoked", keyType),
		Decode:          decodeBalance(keyType),
	})
}

// decodeBalance distinguishes a genuine GET /v1/balance success body from the
// error body Stripe returns on 403 for a restricted key lacking Balance-read
// permission, without needing the response status code (which DecodeFunc does
// not receive): a balance response has no "error" object.
func decodeBalance(keyType string) func(io.Reader) (map[string]string, string, error) {
	return func(body io.Reader) (map[string]string, string, error) {
		var resp struct {
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.NewDecoder(body).Decode(&resp); err != nil {
			return nil, "", err
		}
		if resp.Error != nil {
			return map[string]string{"key_type": keyType, "scope": "restricted"}, "", nil
		}
		return map[string]string{"key_type": keyType}, "", nil
	}
}

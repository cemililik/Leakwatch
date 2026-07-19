// Package sendgrid provides a verifier for SendGrid API keys.
// It uses the SendGrid API GET /v3/scopes endpoint to check key validity.
// That endpoint returns the scopes granted to the key itself and requires no
// particular permission, so every valid key can reach it regardless of how it
// is scoped. This avoids misclassifying a valid but narrowly scoped (restricted)
// key as invalid: a scoped endpoint such as /v3/user/profile returns 403 for a
// live key lacking that specific scope, which must not read as revoked.
package sendgrid

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "sendgrid-api-key"

// defaultAPIURL is the base URL for the SendGrid API.
const defaultAPIURL = "https://api.sendgrid.com"

// Verifier checks whether a SendGrid API key is active by calling the
// SendGrid API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the SendGrid API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify checks if the detected SendGrid API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "sendgrid",
		Request: httpx.Request{
			URL:    apiURL + "/v3/scopes",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		// Only 401 (default) maps to inactive. A 403 is NOT folded into inactive:
		// /v3/scopes needs no specific permission, so a 403 here is an unexpected
		// condition (indeterminate) rather than proof the key is revoked, and it
		// falls through to a verify error instead of a false negative.
		ActiveMessage:   "SendGrid API key is active",
		InactiveMessage: "SendGrid API key is invalid or revoked",
		Decode:          decodeScopes,
	})
}

// decodeScopes reports the number of scopes granted to the key as non-secret
// correlation context. It never returns any scope value or secret material.
func decodeScopes(body io.Reader) (map[string]string, string, error) {
	var payload struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		return nil, "", err
	}
	return map[string]string{"scope_count": strconv.Itoa(len(payload.Scopes))}, "", nil
}

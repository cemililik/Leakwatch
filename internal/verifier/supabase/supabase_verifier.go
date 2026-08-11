// Package supabase provides a verifier for Supabase personal access tokens. It
// uses the Supabase Management API GET /v1/projects endpoint to check validity.
package supabase

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "supabase-service-key"

// defaultAPIURL is the base URL for the Supabase Management API.
const defaultAPIURL = "https://api.supabase.com"

// Verifier checks whether a Supabase personal access token is active by calling
// the Supabase Management API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Supabase API base URL (for testing).
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

// Verify checks if the detected Supabase personal access token is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "supabase",
		Request: httpx.Request{
			URL:    apiURL + "/v1/projects",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Supabase personal access token is active",
		InactiveMessage: "Supabase personal access token is invalid or revoked",
	})
}

// Package grafana provides a verifier for Grafana API keys.
// It uses the Grafana HTTP API GET /api/user endpoint to check key validity.
package grafana

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "grafana-api-key"

// defaultAPIURL is the base URL for the Grafana Cloud API.
const defaultAPIURL = "https://grafana.com"

// Verifier checks whether a Grafana API key is active by calling the
// Grafana Cloud API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Grafana Cloud API base URL (for testing).
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

// Verify checks if the detected Grafana API key is valid/active.
// Raw contains the key value.
//
// This calls GET /api/user, matching docs/architecture/05-VERIFIER-ANALYSIS.md
// and docs/guides/secret-verification.md (the code previously called the
// nonexistent /api/viewer path). Note the caveat those docs already record:
// glsa_ tokens are Grafana Cloud service-account tokens scoped to the stack
// that issued them, so a token minted on a self-hosted or per-stack instance
// will not authenticate against the central grafana.com host used here —
// there is currently no per-instance URL captured for this detector to
// verify against, the same limitation documented for Okta.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "grafana",
		Request: httpx.Request{
			URL:    apiURL + "/api/user",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Grafana API key is active",
		InactiveMessage: "Grafana API key is invalid or revoked",
	})
}

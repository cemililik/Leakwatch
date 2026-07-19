// Package npm provides a verifier for npm authentication tokens.
// It uses the npm registry GET /-/npm/v1/user endpoint to check token validity.
package npm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "npm-token"

// defaultAPIURL is the base URL for the npm registry.
const defaultAPIURL = "https://registry.npmjs.org"

// Verifier checks whether an npm token is active by calling the
// npm registry. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the npm registry base URL (for testing).
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

// Verify checks if the detected npm token is valid/active.
// Raw contains the token value.
//
// This calls GET /-/npm/v1/user, matching
// docs/architecture/05-VERIFIER-ANALYSIS.md and
// docs/guides/secret-verification.md (the code previously called the lighter,
// undocumented /-/whoami endpoint, which is real and functionally
// equivalent, but disagreed with the documented egress target).
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "npm",
		Request: httpx.Request{
			URL:    apiURL + "/-/npm/v1/user",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "npm token is active",
		InactiveMessage: "npm token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser reports the account name as username. The npm profile endpoint
// returns the username in a "name" field (not "username").
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": user.Name}, "", nil
}

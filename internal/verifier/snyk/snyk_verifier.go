// Package snyk provides a verifier for Snyk API keys.
// It uses the Snyk REST API GET /rest/self endpoint to check key validity.
package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "snyk-api-key"

// apiVersion is the Snyk REST API version. The REST API mandates a
// ?version=YYYY-MM-DD query parameter; omitting it makes the API respond 400.
const apiVersion = "2024-10-15"

// Verifier checks whether a Snyk API key is active by calling the
// Snyk REST API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL is reserved for a validated, trusted Snyk API origin. The
	// production registration leaves it empty until operator wiring exists;
	// tests inject a local server.
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

// Verify checks if the detected Snyk API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted Snyk API origin is not configured",
		}
	}
	apiURL := v.apiURL

	// The Snyk REST API requires the version as a query parameter; without it
	// the live API returns 400. The Version header is kept for compatibility.
	endpoint := apiURL + "/rest/self?version=" + url.QueryEscape(apiVersion)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "snyk",
		Request: httpx.Request{
			URL: endpoint,
			Header: map[string]string{
				"Authorization": "token " + token,
				"Version":       apiVersion,
			},
		},
		InactiveStatuses:       []int{http.StatusUnauthorized},
		ActiveMessage:          "Snyk API key is active",
		InactiveMessage:        "Snyk API key is invalid or revoked",
		Decode:                 decodeSelf,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeSelf(body io.Reader) (map[string]string, string, error) {
	var response struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, "", err
	}
	if len(response.Data) == 0 || string(response.Data) == "null" {
		return nil, "", fmt.Errorf("missing Snyk self data")
	}
	return nil, "", nil
}

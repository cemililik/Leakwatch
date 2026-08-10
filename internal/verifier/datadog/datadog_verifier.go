// Package datadog provides a verifier for Datadog API keys.
// It uses the Datadog API GET /api/v1/validate endpoint to check key validity.
package datadog

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

const detectorID = "datadog-api-key"

// Verifier checks whether a Datadog API key is active by calling the
// Datadog validation API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL is reserved for a validated, trusted Datadog site origin. The
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

// Verify checks if the detected Datadog API key is valid/active.
// Raw contains the key value. Datadog returns 200 with a "valid" flag and uses
// 403 (not 401) for a rejected key.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted Datadog site is not configured",
		}
	}
	apiURL := v.apiURL

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "datadog",
		Request: httpx.Request{
			URL:    apiURL + "/api/v1/validate",
			Header: map[string]string{"DD-API-KEY": token},
		},
		InactiveStatuses:       []int{http.StatusForbidden},
		ActiveMessage:          "Datadog API key is active",
		InactiveMessage:        "Datadog API key is invalid or revoked",
		Decode:                 decodeValidate,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

// decodeValidate downgrades a 200 response to inactive when valid=false.
func decodeValidate(body io.Reader) (map[string]string, string, error) {
	var resp struct {
		Valid *bool `json:"valid"`
	}
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, "", err
	}
	if resp.Valid == nil {
		return nil, "", fmt.Errorf("missing Datadog valid field")
	}
	if !*resp.Valid {
		return nil, "Datadog API key is invalid", nil
	}
	return nil, "", nil
}

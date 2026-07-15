// Package okta provides a verifier for Okta API tokens.
// It uses the Okta Users API GET /api/v1/users/me endpoint to check token validity.
// Okta uses the SSWS authorization scheme, not Bearer.
package okta

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

const detectorID = "okta-api-token"

// Verifier checks whether an Okta API token is active by calling the
// Okta Users API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Okta API base URL (for testing).
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

// Verify checks if the detected Okta API token is valid/active.
// The Okta domain is taken from raw.ExtraData["domain"] when apiURL is unset.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	apiURL := v.apiURL
	if apiURL == "" {
		domain, ok := raw.ExtraData["domain"]
		if !ok || domain == "" {
			// Without a co-located Okta org domain the token cannot be routed to
			// a host, so the outcome is indeterminate — never a false "invalid".
			return finding.VerificationResult{
				Status:  finding.StatusUnverified,
				Message: "Okta domain required",
			}
		}
		apiURL = "https://" + domain
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "okta",
		Request: httpx.Request{
			URL:    apiURL + "/api/v1/users/me",
			Header: map[string]string{"Authorization": "SSWS " + token},
		},
		ActiveMessage:   "Okta API token is active",
		InactiveMessage: "Okta API token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser reports the profile login as login.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Profile struct {
			Login string `json:"login"`
		} `json:"profile"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"login": user.Profile.Login}, "", nil
}

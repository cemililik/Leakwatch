// Package auth0 provides a verifier for Auth0 Management API tokens.
// It uses the Auth0 Management API GET /api/v2/ endpoint with Bearer auth
// to check token validity. The Auth0 Management API is tenant-scoped, so the
// target host is derived from the token's own iss claim rather than a fixed host.
package auth0

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "auth0-management-token"

// Verifier checks whether an Auth0 Management API token is active by calling
// the Auth0 Management API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Auth0 API base URL (for testing).
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

// Verify checks if the detected Auth0 Management API token is valid/active.
//
// An Auth0 Management API token is a JWT that is only valid against its own
// tenant's domain. The tenant host is taken from the token's iss claim (when
// apiURL is not overridden for testing). A non-JWT input, or a JWT without an
// iss claim, is indeterminate: the token cannot be routed to a tenant, so the
// result is StatusUnverified rather than a false "invalid".
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
		issuer, ok := issuerFromJWT(token)
		if !ok {
			return finding.VerificationResult{
				Status:  finding.StatusUnverified,
				Message: "Auth0 tenant domain could not be determined from token",
			}
		}
		apiURL = strings.TrimSuffix(issuer, "/")
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "auth0",
		Request: httpx.Request{
			URL:    apiURL + "/api/v2/",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Auth0 management token is active",
		InactiveMessage: "Auth0 management token is invalid or expired",
	})
}

// issuerFromJWT decodes the unverified payload segment of a JWT and returns its
// iss claim, which for an Auth0 Management token is the tenant domain URL
// (for example "https://acme.eu.auth0.com/"). The signature is intentionally
// NOT validated: the claim is used only to route the verification request to
// the correct tenant host, and validity is decided by the live API call. It
// returns ok=false for a non-JWT input or a missing/empty iss claim.
func issuerFromJWT(token string) (issuer string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}

	// JWT segments use base64url without padding, but tolerate padded input.
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", false
	}

	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	if claims.Iss == "" {
		return "", false
	}
	return claims.Iss, true
}

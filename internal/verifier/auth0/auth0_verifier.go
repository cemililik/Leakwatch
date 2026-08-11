// Package auth0 provides a verifier for Auth0 Management API tokens.
// It uses the Auth0 Management API GET /api/v2/ endpoint with Bearer auth
// to check token validity. The Auth0 Management API is tenant-scoped, so the
// target host must be explicitly trusted by the operator. Repository content
// and unverified JWT claims never select the request destination.
package auth0

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

const detectorID = "auth0-management-token"

const clientsProbePath = "/api/v2/clients?per_page=1&include_fields=true&fields=client_id"

// Verifier checks whether an Auth0 Management API token is active by calling
// the Auth0 Management API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Auth0 API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

// NewForTrustedInstance constructs an Auth0 verifier for an origin explicitly
// supplied by the operator. It must never receive an issuer decoded from an
// unverified token or a URL extracted from scanned repository content.
func NewForTrustedInstance(instanceURL string) (*Verifier, error) {
	normalized, err := verifier.NormalizeTrustedHTTPSOrigin(instanceURL)
	if err != nil {
		return nil, err
	}
	return &Verifier{apiURL: normalized}, nil
}

// WithTrustedInstance implements verifier.TrustedInstanceConfigurer.
func (*Verifier) WithTrustedInstance(instanceURL string) (verifier.Verifier, error) {
	return NewForTrustedInstance(instanceURL)
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
// Auth0 Management API tokens are tenant-scoped. Without an operator-trusted
// tenant origin the result is indeterminate and no request is sent.
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
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted Auth0 tenant origin is not configured",
		}
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "auth0",
		Request: httpx.Request{
			URL:    apiURL + clientsProbePath,
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:          "Auth0 management token is active",
		InactiveMessage:        "Auth0 management token is invalid or expired",
		Decode:                 decodeClients,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeClients(body io.Reader) (map[string]string, string, error) {
	var clients []struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(body).Decode(&clients); err != nil {
		return nil, "", err
	}
	if clients == nil {
		return nil, "", fmt.Errorf("Auth0 clients response is not an array")
	}
	return nil, "", nil
}

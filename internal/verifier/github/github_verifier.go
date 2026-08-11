// Package github provides a verifier for GitHub personal access tokens.
// It uses the GitHub API GET /user endpoint to check token validity.
package github

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

const detectorID = "github-token"

// Verifier checks whether a GitHub token is active by calling the
// GitHub API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL is reserved for a validated, trusted GitHub.com or GHES API
	// origin. The production registration leaves it empty until operator wiring
	// exists; tests inject a local server.
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

// NewForTrustedInstance constructs a GitHub PAT verifier for an origin chosen
// explicitly by the operator (GitHub.com API or a GHES API origin).
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

// Verify checks if the detected GitHub token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted GitHub API origin is not configured",
		}
	}
	apiURL := v.apiURL

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "github",
		Request: httpx.Request{
			URL: apiURL + "/user",
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Accept":        "application/vnd.github+json",
			},
		},
		ActiveMessage:          "GitHub token is active",
		InactiveMessage:        "GitHub token is invalid or revoked",
		Decode:                 decodeUser,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

// decodeUser parses the GitHub API response for a valid token.
//
// Enhancement note: a classic PAT's granted scopes are exposed by GitHub in
// the X-OAuth-Scopes response header, not the body, and would be valuable
// triage signal (a repo-scoped token is materially more critical than a
// read:user-scoped one). Surfacing it requires httpx.DecodeFunc to receive
// the response headers, which it currently does not (body-only) — that is a
// change to internal/verifier/internal/httpx, outside this package.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	if user.Login == "" {
		return nil, "", fmt.Errorf("missing GitHub user login")
	}
	return map[string]string{"login": user.Login}, "", nil
}

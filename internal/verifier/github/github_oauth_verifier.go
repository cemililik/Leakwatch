// Package github also provides a verifier for GitHub OAuth tokens.
// It uses the GitHub API GET /user endpoint to check token validity.
package github

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

const oauthDetectorID = "github-oauth-token"

// OAuthVerifier checks whether a GitHub OAuth token is active by calling the
// GitHub API. It NEVER logs or persists raw token values.
type OAuthVerifier struct {
	// apiURL is reserved for a validated, trusted GitHub.com or GHES API
	// origin. The production registration leaves it empty until operator wiring
	// exists; tests inject a local server.
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

func init() {
	verifier.Register(&OAuthVerifier{})
}

// Type returns the detector ID this verifier handles.
func (v *OAuthVerifier) Type() string {
	return oauthDetectorID
}

// Verify checks if the detected GitHub OAuth token is valid/active.
// Raw contains the token value.
func (v *OAuthVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
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
		Name: "github oauth",
		Request: httpx.Request{
			URL: apiURL + "/user",
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Accept":        "application/vnd.github+json",
			},
		},
		ActiveMessage:   "GitHub OAuth token is active",
		InactiveMessage: "GitHub OAuth token is invalid or revoked",
		Decode:          decodeOAuthUser,
	})
}

// decodeOAuthUser parses the GitHub API response for a valid OAuth token.
func decodeOAuthUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"login": user.Login}, "", nil
}

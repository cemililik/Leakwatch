// Package github also provides a verifier for GitHub OAuth tokens.
// It uses the GitHub API GET /user endpoint to check token validity.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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

// NewOAuthForTrustedInstance constructs a subtype-aware GitHub App/OAuth
// verifier for an explicit GitHub.com or GHES API origin.
func NewOAuthForTrustedInstance(instanceURL string) (*OAuthVerifier, error) {
	normalized, err := verifier.NormalizeTrustedHTTPSOrigin(instanceURL)
	if err != nil {
		return nil, err
	}
	return &OAuthVerifier{apiURL: normalized}, nil
}

// WithTrustedInstance implements verifier.TrustedInstanceConfigurer.
func (*OAuthVerifier) WithTrustedInstance(instanceURL string) (verifier.Verifier, error) {
	return NewOAuthForTrustedInstance(instanceURL)
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
	path := "/user"
	var decode httpx.DecodeFunc
	var decodeResponse httpx.ResponseDecodeFunc
	switch {
	case strings.HasPrefix(token, "gho_"), strings.HasPrefix(token, "ghu_"):
		// OAuth and GitHub App user access tokens authenticate a user.
		decodeResponse = decodeUserResponse
	case strings.HasPrefix(token, "ghs_"):
		// Installation tokens do not support GET /user. This endpoint is a
		// read-only identity-safe probe and works even when the installation has
		// access to zero repositories.
		path = "/installation/repositories"
		decode = decodeInstallationRepositories
	case strings.HasPrefix(token, "ghr_"):
		// Verifying a refresh token requires exchanging it, which rotates the
		// token. A verifier must never create that side effect.
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "GitHub refresh token cannot be verified without rotating it",
		}
	default:
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "unsupported GitHub token subtype",
		}
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "github oauth",
		Request: httpx.Request{
			URL: apiURL + path,
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Accept":        "application/vnd.github+json",
			},
		},
		ActiveMessage:          "GitHub OAuth or installation token is active",
		InactiveMessage:        "GitHub OAuth or installation token is invalid or revoked",
		Decode:                 decode,
		DecodeResponse:         decodeResponse,
		DecodeInactive:         decodeGitHubInactive,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeInstallationRepositories(body io.Reader) (map[string]string, string, error) {
	var response struct {
		TotalCount *int `json:"total_count"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&response); err != nil {
		return nil, "", err
	}
	if err := requireGitHubJSONEOF(decoder); err != nil {
		return nil, "", err
	}
	if response.TotalCount == nil || *response.TotalCount < 0 {
		return nil, "", fmt.Errorf("missing GitHub installation repository count")
	}
	return map[string]string{"token_subtype": "ghs"}, "", nil
}

// Package gitlab provides a verifier for GitLab personal access tokens.
// It uses the GitLab API GET /api/v4/user endpoint to check token validity.
package gitlab

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

const detectorID = "gitlab-pat"

// defaultHost is the GitLab SaaS host, used when no self-hosted instance host
// was captured alongside the token.
const defaultHost = "gitlab.com"

// Verifier checks whether a GitLab personal access token is active by calling
// the GitLab API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the GitLab API base URL (for testing).
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

// Verify checks if the detected GitLab personal access token is valid/active.
// Raw contains the token value. The API host is derived from a co-located
// self-hosted instance host (ExtraData["host"]) when present, defaulting to
// gitlab.com — so an active self-hosted token is verified against its true
// issuer instead of being misreported as invalid by gitlab.com.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := v.baseURL(raw)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "gitlab",
		Request: httpx.Request{
			URL:    apiURL + "/api/v4/user",
			Header: map[string]string{"PRIVATE-TOKEN": token},
		},
		ActiveMessage:   "GitLab token is active",
		InactiveMessage: "GitLab token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// baseURL resolves the GitLab API base URL. A test-injected apiURL wins;
// otherwise the co-located self-hosted host (ExtraData["host"]) is used, falling
// back to gitlab.com. raw.ExtraData may be nil (safe to index).
func (v *Verifier) baseURL(raw detector.RawFinding) string {
	if v.apiURL != "" {
		return v.apiURL
	}
	host := defaultHost
	if h := raw.ExtraData["host"]; h != "" {
		host = h
	}
	return "https://" + host
}

// decodeUser parses the GitLab API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": user.Username}, "", nil
}

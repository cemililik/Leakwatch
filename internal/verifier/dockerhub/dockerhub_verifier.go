// Package dockerhub provides a verifier for Docker Hub Personal Access Tokens.
// It uses the Docker Hub API GET /v2/user/ endpoint to check token validity.
package dockerhub

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

const detectorID = "dockerhub-pat"

// defaultAPIURL is the base URL for the Docker Hub API.
const defaultAPIURL = "https://hub.docker.com"

// Verifier checks whether a Docker Hub PAT is active by calling the
// Docker Hub API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Docker Hub API base URL (for testing).
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

// Verify checks if the detected Docker Hub PAT is valid/active.
// Raw contains the token value.
//
// Docker Hub Personal Access Tokens are sent directly as an Authorization:
// Bearer header on the v2 API, without a preceding login/JWT-exchange step:
// Docker's own access-token documentation confirms PATs authenticate the Hub
// API directly (https://docs.docker.com/security/access-tokens/), and the
// legacy POST /v2/users/login/ JWT-exchange flow is documented to reject
// tokens minted from a PAT ("token issued from personal access token") on
// many endpoints, so it is not a viable alternative here. That flow would
// also require the token's Docker Hub username, which this package's
// detector does not capture (only the PAT itself is matched) — a second,
// independent reason the login-exchange is not implementable for this
// verifier.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "dockerhub",
		Request: httpx.Request{
			URL:    apiURL + "/v2/user/",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Docker Hub PAT is active",
		InactiveMessage: "Docker Hub PAT is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the Docker Hub API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": user.Username}, "", nil
}

// Package gitlab provides a verifier for GitLab personal access tokens.
// It uses the GitLab API GET /api/v4/user endpoint to check token validity.
package gitlab

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "gitlab-pat"

// Verifier checks whether a GitLab personal access token is active by calling
// the GitLab API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the GitLab API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

// NewForTrustedInstance constructs a GitLab verifier for an API origin
// explicitly supplied by the operator. Finding metadata and scanned URLs are
// deliberately never accepted as routing authority.
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

// Verify checks if the detected GitLab personal access token is valid/active.
// Raw contains the token value. Only personal access tokens (`glpat-`) can use
// the read-only `/user` probe. Other GitLab credential families have different
// authentication contracts and remain unverified.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if !strings.HasPrefix(token, "glpat-") {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "GitLab token subtype has no safe universal verification probe",
		}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted GitLab API origin is not configured",
		}
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "gitlab",
		Request: httpx.Request{
			URL:    v.apiURL + "/api/v4/user",
			Header: map[string]string{"PRIVATE-TOKEN": token},
		},
		ActiveMessage:   "GitLab token is active",
		InactiveMessage: "GitLab token is invalid or revoked",
		Decode:          decodeUser,
	})
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

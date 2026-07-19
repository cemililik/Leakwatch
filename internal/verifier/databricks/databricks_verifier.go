// Package databricks provides a verifier for Databricks personal access tokens.
// A Databricks PAT is workspace-scoped and authenticates only against its own
// workspace host (for example https://dbc-xxxx.cloud.databricks.com), never the
// account-level host. The verifier therefore calls the workspace SCIM API
// GET /api/2.0/preview/scim/v2/Me on the workspace host provided by the detector
// via ExtraData["host"]; when no host is available it returns an indeterminate
// (format-only) result rather than making a wrong-host call.
package databricks

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

const detectorID = "databricks-token"

// Verifier checks whether a Databricks personal access token is active by calling
// the Databricks SCIM API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Databricks API base URL (for testing).
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

// Verify checks if the detected Databricks token is valid/active.
// Raw contains the token value; the workspace host is read from
// ExtraData["host"]. Without a workspace host the token cannot be verified
// against the correct instance, so the result is indeterminate (unverified).
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	// Prefer the test-injected base URL, then the detector-captured workspace
	// host. A Databricks PAT is only valid against its own workspace host, so
	// without one we cannot make a correct live call.
	apiURL := v.apiURL
	if apiURL == "" && raw.ExtraData != nil {
		apiURL = strings.TrimRight(raw.ExtraData["host"], "/")
	}
	if apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format valid; workspace host required for live verification (not found alongside token)",
		}
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "databricks",
		Request: httpx.Request{
			URL:    apiURL + "/api/2.0/preview/scim/v2/Me",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Databricks token is active",
		InactiveMessage: "Databricks token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the Databricks SCIM API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		UserName string `json:"userName"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"userName": user.UserName}, "", nil
}

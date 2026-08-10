// Package grafana provides a verifier for Grafana service-account tokens.
// It uses the issuing instance's read-only access-control permissions endpoint.
package grafana

import (
	"context"
	"net/http"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "grafana-api-key"

const permissionsPath = "/api/access-control/user/permissions"

// Verifier checks whether a Grafana service-account token is active against
// its issuing instance. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL is a trusted Grafana instance base URL supplied by the application.
	// It is intentionally unexported and currently used only by hermetic tests;
	// repository content and RawFinding.ExtraData must never populate it because
	// doing so would turn verification into an SSRF primitive.
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

// Verify checks if the detected Grafana service-account token is valid/active.
// Raw contains the key value.
//
// Grafana service-account tokens are scoped to the instance that issued them.
// The detector does not currently have a trusted instance URL, so the
// production-registered verifier deliberately performs no request and returns
// unverified. In particular, it never trusts an arbitrary URL extracted from
// repository content or falls back to the central grafana.com portal.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "Grafana instance URL required",
		}
	}
	apiURL := strings.TrimRight(v.apiURL, "/")

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "grafana",
		Request: httpx.Request{
			URL:    apiURL + permissionsPath,
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Grafana API key is active",
		InactiveMessage: "Grafana API key is invalid or revoked",
	})
}

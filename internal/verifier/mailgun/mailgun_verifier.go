// Package mailgun provides a verifier for Mailgun API keys.
// It uses the Mailgun API GET /v3/domains endpoint with Basic auth to check key
// validity, retrying against the EU-region host when the US host reports the
// key inactive.
package mailgun

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "mailgun-api-key"

// defaultAPIURL is the base URL for the Mailgun US-region API.
const defaultAPIURL = "https://api.mailgun.net"

// defaultEUAPIURL is the base URL for the Mailgun EU-region API. Mailgun
// operates the US and EU regions as separate, non-interoperable tenants: a
// key valid only in the EU region is rejected by the US host, and vice versa.
const defaultEUAPIURL = "https://api.eu.mailgun.net"

// Verifier checks whether a Mailgun API key is active by calling the
// Mailgun API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Mailgun US API base URL (for testing).
	apiURL string
	// euAPIURL overrides the Mailgun EU API base URL (for testing).
	euAPIURL string
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

// Verify checks if the detected Mailgun API key is valid/active.
// Raw contains the key value.
//
// Mailgun keys carry no region marker, so there is no way to tell from the
// key alone whether it belongs to a US or EU-provisioned account. Verify
// therefore probes the US host first (the common case) and, only if that
// reports the key inactive, retries against the EU host before concluding
// the key is genuinely dead — otherwise a live EU key would always be
// misreported as inactive. A transport error or a cancelled context on the
// first probe is never treated as "inactive", so it is returned as-is
// without a second call.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)

	usURL := httpx.BaseURL(v.apiURL, defaultAPIURL)
	result := verifyDomains(ctx, v.httpClient, token, usURL)
	if result.Status != finding.StatusVerifiedInactive {
		return result
	}

	slog.DebugContext(ctx, "mailgun verifier: US host reports inactive, retrying against EU host")
	euURL := httpx.BaseURL(v.euAPIURL, defaultEUAPIURL)
	return verifyDomains(ctx, v.httpClient, token, euURL)
}

// verifyDomains performs the Mailgun GET /v3/domains check against apiURL.
func verifyDomains(ctx context.Context, httpClient *http.Client, token, apiURL string) finding.VerificationResult {
	return httpx.VerifyToken(ctx, httpClient, token, httpx.TokenSpec{
		Name: "mailgun",
		Request: httpx.Request{
			URL:           apiURL + "/v3/domains",
			BasicAuthUser: "api",
			BasicAuthPass: token,
		},
		ActiveMessage:   "Mailgun API key is active",
		InactiveMessage: "Mailgun API key is invalid or revoked",
	})
}

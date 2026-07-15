// Package twilio provides a verifier for Twilio API keys.
// It uses the Twilio Accounts API GET /2010-04-01/Accounts.json endpoint
// with Basic auth to check key validity.
package twilio

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "twilio-api-key"

// defaultAPIURL is the base URL for the Twilio API.
const defaultAPIURL = "https://api.twilio.com"

// Verifier checks whether a Twilio API key is active by calling the
// Twilio Accounts API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Twilio API base URL (for testing).
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

// Verify checks if the detected Twilio API key is valid/active.
//
// The detector emits the API Key SID ("SK...") as raw.Raw and the Account SID
// ("AC...") as raw.ExtraData["account_sid"]. Twilio's REST API accepts exactly
// two Basic-Auth pairs: (Account SID, Auth Token) or (API Key SID, API Key
// Secret). Since raw.Raw is an API Key SID, the only valid pairing is
// (API Key SID, API Key Secret): the SID is the Basic-Auth username and the
// paired API Key Secret is the password. The API Key SID alone is a non-secret
// identifier and cannot authenticate on its own, so when the paired secret is
// not available (raw.ExtraData["api_key_secret"] is empty) the key is reported
// as Unverified — never as inactive, which would misread a live but unpaired
// credential as revoked.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	apiKeySID := string(raw.Raw)
	if apiKeySID == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	var accountSID, apiKeySecret string
	if raw.ExtraData != nil {
		accountSID = raw.ExtraData["account_sid"]
		apiKeySecret = raw.ExtraData["api_key_secret"]
	}

	if apiKeySecret == "" {
		// Without the paired API Key Secret the credential cannot be
		// authenticated. Report Unverified rather than guessing at liveness.
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "API Key Secret unavailable; cannot verify",
		}
	}

	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)
	// When the Account SID is known, scope the request to that account;
	// otherwise fall back to the accounts collection, which an API Key can also
	// reach.
	path := "/2010-04-01/Accounts.json"
	if accountSID != "" {
		path = "/2010-04-01/Accounts/" + accountSID + ".json"
	}

	return httpx.VerifyToken(ctx, v.httpClient, apiKeySID, httpx.TokenSpec{
		Name: "twilio",
		Request: httpx.Request{
			URL:           apiURL + path,
			BasicAuthUser: apiKeySID,
			BasicAuthPass: apiKeySecret,
		},
		ActiveMessage:   "Twilio API key is active",
		InactiveMessage: "Twilio API key is invalid or revoked",
	})
}

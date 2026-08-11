// Package twilio provides conservative verification for paired Twilio API Key
// credentials. Production makes no request until a trusted regional API origin
// is supplied by operator-controlled configuration.
package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "twilio-api-key"

var (
	apiKeySIDPattern  = regexp.MustCompile(`^SK[0-9a-fA-F]{32}$`)
	accountSIDPattern = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)
)

// Verifier checks a Twilio API Key Secret with its paired API Key SID. apiURL
// is an unexported trusted-origin seam; the production registration leaves it
// empty because Twilio credentials are region-specific.
type Verifier struct {
	apiURL     string
	httpClient *http.Client
}

// NewForTrustedInstance accepts an operator-selected official Twilio regional
// API origin. Region selection is never inferred from scanned content.
func NewForTrustedInstance(instanceURL string) (*Verifier, error) {
	normalized, err := verifier.NormalizeTrustedHTTPSOrigin(instanceURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(normalized)
	hostname := u.Hostname()
	if err != nil || u.Port() != "" ||
		(hostname != "api.twilio.com" &&
			(!strings.HasPrefix(hostname, "api.") || !strings.HasSuffix(hostname, ".twilio.com"))) {
		return nil, errors.New("invalid Twilio API origin: an official twilio.com host is required")
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
func (v *Verifier) Type() string { return detectorID }

// Verify authenticates with API Key SID as the Basic username and API Key
// Secret as the password. Main, Standard, and Restricted keys have different
// permissions: only 401 proves inactive; a permission-denied 403 is
// deliberately a verify_error.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	apiKeySecret := string(raw.Raw)
	if apiKeySecret == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}

	apiKeySID := ""
	accountSID := ""
	if raw.ExtraData != nil {
		apiKeySID = raw.ExtraData["api_key_sid"]
		accountSID = raw.ExtraData["account_sid"]
	}
	if !apiKeySIDPattern.MatchString(apiKeySID) {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "paired Twilio API Key SID is required for verification",
		}
	}
	if accountSID != "" && !accountSIDPattern.MatchString(accountSID) {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "invalid Twilio Account SID context",
		}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted Twilio regional API origin is not configured",
		}
	}

	path := "/2010-04-01/Accounts.json"
	if accountSID != "" {
		path = "/2010-04-01/Accounts/" + accountSID + ".json"
	}

	return httpx.VerifyToken(ctx, v.httpClient, apiKeySecret, httpx.TokenSpec{
		Name: "twilio",
		Request: httpx.Request{
			URL:           v.apiURL + path,
			BasicAuthUser: apiKeySID,
			BasicAuthPass: apiKeySecret,
		},
		InactiveStatuses:       []int{http.StatusUnauthorized},
		ActiveMessage:          "Twilio API key is active for the trusted region and probe",
		InactiveMessage:        "Twilio API key is invalid or revoked on the trusted region",
		Decode:                 func(body io.Reader) (map[string]string, string, error) { return decodeAccountProbe(body, accountSID) },
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeAccountProbe(body io.Reader, expectedAccountSID string) (map[string]string, string, error) {
	var response struct {
		SID      string          `json:"sid"`
		Accounts json.RawMessage `json:"accounts"`
	}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, "", err
	}
	if expectedAccountSID != "" {
		if response.SID != expectedAccountSID {
			return nil, "", errors.New("twilio account probe returned an unexpected account")
		}
		return map[string]string{"account_sid": expectedAccountSID}, "", nil
	}
	if len(response.Accounts) == 0 || string(response.Accounts) == "null" {
		return nil, "", errors.New("twilio account collection is missing")
	}
	return nil, "", nil
}

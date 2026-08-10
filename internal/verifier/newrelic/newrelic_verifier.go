// Package newrelic provides a verifier for New Relic user API keys.
// It uses a read-only NerdGraph requestContext query against New Relic's
// officially documented US and EU endpoints.
package newrelic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	detectorID = "newrelic-api-key"

	usNerdGraphURL = "https://api.newrelic.com/graphql"
	euNerdGraphURL = "https://api.eu.newrelic.com/graphql"

	requestContextQuery = `{"query":"query LeakwatchVerifyKey { requestContext { userId } }"}`
)

type endpoint struct {
	region string
	url    string
}

var officialEndpoints = []endpoint{
	{region: "US", url: usNerdGraphURL},
	{region: "EU", url: euNerdGraphURL},
}

// Verifier checks whether a New Relic user API key is active. It NEVER logs or
// persists raw token values. endpoints and httpClient are hermetic test seams;
// production uses the fixed officialEndpoints list and hardened shared client.
type Verifier struct {
	endpoints  []endpoint
	httpClient *http.Client
}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// VerificationRequestBudget returns the maximum number of HTTP probes this
// verifier can issue for one finding. The verification engine enforces this
// bound while admitting each actual request at its send point.
func (v *Verifier) VerificationRequestBudget() int {
	return len(v.resolvedEndpoints())
}

// Verify checks the key against New Relic's fixed US/EU NerdGraph endpoints.
// A 401 from one region is not revocation evidence because the key may belong
// to the other region. The key is inactive only when every supported region
// returns 401; any successful region wins, while permission/network/provider
// errors keep the outcome inconclusive.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return v.verify(ctx, raw, nil)
}

// VerifyWithRequestGate checks every actual regional request through the
// engine-owned rate limiter immediately before sending it. The fallback region
// consumes no token unless it is genuinely attempted.
func (v *Verifier) VerifyWithRequestGate(
	ctx context.Context,
	raw detector.RawFinding,
	gate verifier.RequestGate,
) finding.VerificationResult {
	return v.verify(ctx, raw, gate)
}

func (v *Verifier) verify(
	ctx context.Context,
	raw detector.RawFinding,
	gate verifier.RequestGate,
) finding.VerificationResult {
	token := string(raw.Raw)
	if strings.TrimSpace(token) == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}

	endpoints := v.resolvedEndpoints()
	unauthorized := 0
	hadInconclusive := false
	for _, target := range endpoints {
		if ctx.Err() != nil {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: "New Relic verification cancelled before all regions were checked",
			}
		}
		if gate != nil {
			if rejection := gate(ctx); rejection != nil {
				return *rejection
			}
		}

		result := v.verifyEndpoint(ctx, token, target)
		switch result.Status {
		case finding.StatusVerifiedActive:
			return result
		case finding.StatusVerifiedInactive:
			unauthorized++
		default:
			hadInconclusive = true
		}
	}

	if unauthorized == len(endpoints) && !hadInconclusive {
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "New Relic API key is invalid or revoked in all supported regions",
		}
	}
	return finding.VerificationResult{
		Status:  finding.StatusVerifyError,
		Message: "New Relic verification was inconclusive across supported regions",
	}
}

func (v *Verifier) resolvedEndpoints() []endpoint {
	if len(v.endpoints) > 0 {
		return v.endpoints
	}
	return officialEndpoints
}

func (v *Verifier) verifyEndpoint(ctx context.Context, token string, target endpoint) finding.VerificationResult {
	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "newrelic-" + strings.ToLower(target.region),
		Request: httpx.Request{
			Method: http.MethodPost,
			URL:    target.url,
			Body:   []byte(requestContextQuery),
			Header: map[string]string{
				"Accept":       "application/json",
				"Api-Key":      token,
				"Content-Type": "application/json",
			},
		},
		ActiveMessage:          "New Relic API key is active (" + target.region + " region)",
		InactiveMessage:        "New Relic API key was rejected by the " + target.region + " region",
		Decode:                 decodeRequestContext,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeRequestContext(body io.Reader) (map[string]string, string, error) {
	var response struct {
		Data *struct {
			RequestContext *struct {
				UserID json.RawMessage `json:"userId"`
			} `json:"requestContext"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&response); err != nil {
		return nil, "", fmt.Errorf("invalid NerdGraph response: %w", err)
	}
	if len(response.Errors) > 0 {
		return nil, "", fmt.Errorf("NerdGraph returned GraphQL errors")
	}
	if response.Data == nil || response.Data.RequestContext == nil ||
		!isValidUserID(response.Data.RequestContext.UserID) {
		return nil, "", fmt.Errorf("NerdGraph response did not identify the API key owner")
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, "", fmt.Errorf("invalid NerdGraph response: trailing JSON value")
		}
		return nil, "", fmt.Errorf("invalid NerdGraph response: %w", err)
	}
	return nil, "", nil
}

func isValidUserID(value json.RawMessage) bool {
	var text string
	if err := json.Unmarshal(value, &text); err == nil {
		return strings.TrimSpace(text) != ""
	}

	var number json.Number
	if err := json.Unmarshal(value, &number); err != nil {
		return false
	}
	id, err := strconv.ParseInt(number.String(), 10, 64)
	return err == nil && id > 0
}

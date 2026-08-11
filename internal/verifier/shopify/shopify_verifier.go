// Package shopify provides fail-closed verification for Shopify Admin API
// access tokens against an operator-trusted store origin.
package shopify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	detectorID = "shopify-access-token"
	// Shopify versions are supported for at least 12 months. This pin is
	// reviewed alongside LastContractReviewedAt in the capability manifest.
	shopifyAPIVersion = "2026-07"
	shopAPIPath       = "/admin/api/" + shopifyAPIVersion + "/graphql.json"
	shopIdentityQuery = `{"query":"query LeakwatchVerify { shop { name } }"}`
)

// Verifier checks a token only when apiURL has been set from trusted operator
// configuration. Finding-controlled store_domain metadata is never used for
// routing, preventing wrong-issuer false-inactive results and credential
// forwarding to an untrusted host.
type Verifier struct {
	apiURL     string
	httpClient *http.Client
}

// NewForTrustedInstance accepts only an operator-selected canonical
// myshopify.com store origin. Custom domains and repository metadata are not
// routing authority for Admin API credentials.
func NewForTrustedInstance(instanceURL string) (*Verifier, error) {
	normalized, err := verifier.NormalizeTrustedHTTPSOrigin(instanceURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Port() != "" || !strings.HasSuffix(u.Hostname(), ".myshopify.com") ||
		strings.TrimSuffix(u.Hostname(), ".myshopify.com") == "" {
		return nil, errors.New("invalid Shopify store origin: a concrete myshopify.com store is required")
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

// Verify performs a read-only GraphQL shop identity query. Only HTTP 401 on
// the trusted store is definitive inactivity; authorization and GraphQL errors
// remain verify_error.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted Shopify store origin is not configured",
		}
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "shopify",
		Request: httpx.Request{
			Method: http.MethodPost,
			URL:    v.apiURL + shopAPIPath,
			Body:   []byte(shopIdentityQuery),
			Header: map[string]string{
				"Accept":                 "application/json",
				"Content-Type":           "application/json",
				"X-Shopify-Access-Token": token,
			},
		},
		InactiveStatuses:       []int{http.StatusUnauthorized},
		ActiveMessage:          "Shopify access token is active on the trusted store",
		InactiveMessage:        "Shopify access token is invalid or revoked on the trusted store",
		Decode:                 decodeShopIdentity,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeShopIdentity(body io.Reader) (map[string]string, string, error) {
	var response struct {
		Data *struct {
			Shop *struct {
				Name string `json:"name"`
			} `json:"shop"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, "", err
	}
	if len(response.Errors) > 0 {
		return nil, "", errors.New("shopify GraphQL response contains errors")
	}
	if response.Data == nil || response.Data.Shop == nil || response.Data.Shop.Name == "" {
		return nil, "", errors.New("shopify GraphQL response is missing shop identity")
	}
	return map[string]string{"shop_name": response.Data.Shop.Name}, "", nil
}

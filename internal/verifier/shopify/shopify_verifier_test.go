package shopify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	shopifydetector "github.com/HodeTech/leakwatch/internal/detector/shopify"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func shopifyFinding() detector.RawFinding {
	return detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("shpat_" + strings.Repeat("ab12cd34", 4)),
		Redacted:   "shpat_****cd34",
	}
}

func TestVerify_TrustedStoreUsesCurrentGraphQLContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/admin/api/2026-07/graphql.json", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, string(shopifyFinding().Raw), r.Header.Get("X-Shopify-Access-Token"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.JSONEq(t, shopIdentityQuery, string(body))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"shop":{"name":"My Test Store"}}}`))
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
		context.Background(), shopifyFinding(),
	)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "Shopify access token is active on the trusted store", result.Message)
	assert.Equal(t, "My Test Store", result.ExtraData["shop_name"])
}

func TestVerify_WithoutTrustedStoreMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	raw := shopifyFinding()
	raw.ExtraData = map[string]string{"store_domain": strings.TrimPrefix(server.URL, "http://")}
	result := (&Verifier{httpClient: server.Client()}).Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "trusted Shopify store origin is not configured", result.Message)
	assert.Zero(t, requests, "finding-controlled store_domain must never select a request target")
}

func TestNewForTrustedInstance_AcceptsOnlyCanonicalShopifyStore(t *testing.T) {
	configured, err := NewForTrustedInstance("https://fixture-store.myshopify.com/")
	require.NoError(t, err)
	assert.Equal(t, "https://fixture-store.myshopify.com", configured.apiURL)
	for _, origin := range []string{
		"https://myshopify.com", "https://fixture-store.myshopify.com.attacker.example",
		"https://fixture-store.myshopify.com:443", "https://custom-store.example",
	} {
		_, err := NewForTrustedInstance(origin)
		assert.Error(t, err, origin)
	}
}

func TestVerify_RealDetectorFindingMatchesRequiresContextCapability(t *testing.T) {
	findings := (&shopifydetector.Detector{}).Scan(context.Background(), shopifyFinding().Raw)
	require.Len(t, findings, 1)

	result := (&Verifier{}).Verify(context.Background(), findings[0])
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "trusted Shopify store origin is not configured", result.Message)
}

func TestVerify_Only401IsInactive(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   finding.VerificationStatus
	}{
		{name: "401 authentication rejection", status: http.StatusUnauthorized, want: finding.StatusVerifiedInactive},
		{name: "403 authorization rejection", status: http.StatusForbidden, want: finding.StatusVerifyError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer server.Close()

			result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
				context.Background(), shopifyFinding(),
			)
			assert.Equal(t, tc.want, result.Status)
		})
	}
}

func TestVerify_MalformedOrGraphQLErrorResponseIsVerifyError(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "missing data", contentType: "application/json", body: `{}`},
		{name: "null shop", contentType: "application/json", body: `{"data":{"shop":null}}`},
		{name: "GraphQL errors", contentType: "application/json", body: `{"errors":[{"message":"denied"}]}`},
		{name: "wrong content type", contentType: "text/html", body: `{"data":{"shop":{"name":"Store"}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
				context.Background(), shopifyFinding(),
			)
			assert.Equal(t, finding.StatusVerifyError, result.Status)
		})
	}
}

func TestVerify_ServerErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := (&Verifier{apiURL: server.URL, httpClient: server.Client()}).Verify(
		context.Background(), shopifyFinding(),
	)
	assert.Equal(t, finding.StatusVerifyError, result.Status)
}

func TestVerify_TypeAndEmptyToken(t *testing.T) {
	assert.Equal(t, detectorID, (&Verifier{}).Type())
	result := (&Verifier{}).Verify(context.Background(), detector.RawFinding{})
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
}

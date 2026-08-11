package newrelic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const testToken = "NRAK-ABC123DEF456GHI789JKL012MNO"

func rawFinding(token string) detector.RawFinding {
	return detector.RawFinding{DetectorID: detectorID, Raw: []byte(token), Redacted: "NRAK-****2MNO"}
}

func TestVerify_NerdGraphRequestAndResponseContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/graphql", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, testToken, r.Header.Get("Api-Key"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, requestContextQuery, string(body))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"requestContext":{"userId":12345}}}`))
	}))
	defer server.Close()

	v := &Verifier{
		endpoints:  []endpoint{{region: "US", url: server.URL + "/graphql"}},
		httpClient: server.Client(),
	}
	result := v.Verify(context.Background(), rawFinding(testToken))

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "New Relic API key is active (US region)", result.Message)
	assert.Empty(t, result.ExtraData, "identity/PII must not be retained")
}

func TestVerify_RegionFallbackDecisionMatrix(t *testing.T) {
	tests := []struct {
		name         string
		statuses     []int
		bodies       []string
		want         finding.VerificationStatus
		wantRequests int32
	}{
		{
			name:     "US unauthorized then EU active",
			statuses: []int{http.StatusUnauthorized, http.StatusOK},
			bodies:   []string{`{"errors":[{"message":"authentication required"}]}`, `{"data":{"requestContext":{"userId":"eu-user"}}}`},
			want:     finding.StatusVerifiedActive, wantRequests: 2,
		},
		{
			name:     "US active stops fallback",
			statuses: []int{http.StatusOK, http.StatusInternalServerError},
			bodies:   []string{`{"data":{"requestContext":{"userId":1}}}`, `{}`},
			want:     finding.StatusVerifiedActive, wantRequests: 1,
		},
		{
			name:     "all regions unauthorized",
			statuses: []int{http.StatusUnauthorized, http.StatusUnauthorized},
			bodies:   []string{`{"errors":[{"message":"authentication required"}]}`, `{"errors":[{"message":"authentication required"}]}`},
			want:     finding.StatusVerifiedInactive, wantRequests: 2,
		},
		{
			name:     "403 is never inactive",
			statuses: []int{http.StatusForbidden, http.StatusUnauthorized},
			bodies:   []string{`{}`, `{"errors":[{"message":"authentication required"}]}`},
			want:     finding.StatusVerifyError, wantRequests: 2,
		},
		{
			name:     "provider failure plus 401 is inconclusive",
			statuses: []int{http.StatusInternalServerError, http.StatusUnauthorized},
			bodies:   []string{`{}`, `{"errors":[{"message":"authentication required"}]}`},
			want:     finding.StatusVerifyError, wantRequests: 2,
		},
		{
			name:     "GraphQL error plus 401 is inconclusive",
			statuses: []int{http.StatusOK, http.StatusUnauthorized},
			bodies:   []string{`{"errors":[{"message":"forbidden"}]}`, `{"errors":[{"message":"authentication required"}]}`},
			want:     finding.StatusVerifyError, wantRequests: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			servers := make([]*httptest.Server, len(tc.statuses))
			endpoints := make([]endpoint, len(tc.statuses))
			for i := range tc.statuses {
				status, body := tc.statuses[i], tc.bodies[i]
				servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_, _ = w.Write([]byte(body))
				}))
				defer servers[i].Close()
				endpoints[i] = endpoint{region: []string{"US", "EU"}[i], url: servers[i].URL}
			}

			v := &Verifier{endpoints: endpoints, httpClient: servers[0].Client()}
			result := v.Verify(context.Background(), rawFinding(testToken))
			assert.Equal(t, tc.want, result.Status)
			assert.Equal(t, tc.wantRequests, requests.Load())
		})
	}
}

func TestVerify_InactiveResponseMustBeDefinitiveJSON(t *testing.T) {
	tests := []struct{ contentType, body string }{
		{contentType: "text/html", body: `<html>proxy login</html>`},
		{contentType: "application/json", body: `{"errors":[{"message":"challenge"}]}`},
	}
	for _, tc := range tests {
		servers := make([]*httptest.Server, 2)
		endpoints := make([]endpoint, 2)
		for i := range servers {
			servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(tc.body))
			}))
			endpoints[i] = endpoint{region: []string{"US", "EU"}[i], url: servers[i].URL}
		}
		result := (&Verifier{endpoints: endpoints, httpClient: servers[0].Client()}).Verify(
			context.Background(), rawFinding(testToken),
		)
		for _, server := range servers {
			server.Close()
		}
		assert.Equal(t, finding.StatusVerifyError, result.Status)
	}
}

func TestVerifyWithRequestGate_AdmitsOnlyActualRegionalRequests(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []int
		bodies    []string
		wantGates int32
		wantCalls int32
	}{
		{
			name:      "US active does not admit unused EU fallback",
			statuses:  []int{http.StatusOK, http.StatusInternalServerError},
			bodies:    []string{`{"data":{"requestContext":{"userId":1}}}`, `{}`},
			wantGates: 1,
			wantCalls: 1,
		},
		{
			name:      "US rejection admits EU immediately before fallback",
			statuses:  []int{http.StatusUnauthorized, http.StatusOK},
			bodies:    []string{`{"errors":[{"message":"authentication required"}]}`, `{"data":{"requestContext":{"userId":2}}}`},
			wantGates: 2,
			wantCalls: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gates atomic.Int32
			var calls atomic.Int32
			servers := make([]*httptest.Server, len(tc.statuses))
			endpoints := make([]endpoint, len(tc.statuses))
			for i := range tc.statuses {
				status, body := tc.statuses[i], tc.bodies[i]
				servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_, _ = w.Write([]byte(body))
				}))
				defer servers[i].Close()
				endpoints[i] = endpoint{region: []string{"US", "EU"}[i], url: servers[i].URL}
			}

			v := &Verifier{endpoints: endpoints, httpClient: servers[0].Client()}
			result := v.VerifyWithRequestGate(context.Background(), rawFinding(testToken), func() *finding.VerificationResult {
				gates.Add(1)
				return nil
			})
			assert.Equal(t, finding.StatusVerifiedActive, result.Status)
			assert.Equal(t, tc.wantGates, gates.Load())
			assert.Equal(t, tc.wantCalls, calls.Load())
		})
	}
}

func TestVerifyWithRequestGate_RejectionPreventsFallbackRequest(t *testing.T) {
	var requests atomic.Int32
	servers := make([]*httptest.Server, 2)
	for i, status := range []int{http.StatusUnauthorized, http.StatusOK} {
		status := status
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"data":{"requestContext":{"userId":2}}}`))
		}))
		defer servers[i].Close()
	}
	v := &Verifier{
		endpoints:  []endpoint{{region: "US", url: servers[0].URL}, {region: "EU", url: servers[1].URL}},
		httpClient: servers[0].Client(),
	}
	var gates atomic.Int32
	result := v.VerifyWithRequestGate(context.Background(), rawFinding(testToken), func() *finding.VerificationResult {
		if gates.Add(1) == 2 {
			return &finding.VerificationResult{Status: finding.StatusVerifyError, Message: "rate limiter cancelled"}
		}
		return nil
	})

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Equal(t, int32(2), gates.Load())
	assert.Equal(t, int32(1), requests.Load(), "rejected admission must happen before the EU request is sent")
}

func TestVerify_InvalidSuccessBodiesAreInconclusive(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "HTML", contentType: "text/html", body: `<html>login</html>`},
		{name: "JSON with HTML media type", contentType: "text/html", body: `{"data":{"requestContext":{"userId":1}}}`},
		{name: "malformed", contentType: "application/json", body: `{not-json`},
		{name: "missing data", contentType: "application/json", body: `{}`},
		{name: "null data", contentType: "application/json", body: `{"data":null}`},
		{name: "null user", contentType: "application/json", body: `{"data":{"requestContext":{"userId":null}}}`},
		{name: "empty user", contentType: "application/json", body: `{"data":{"requestContext":{"userId":""}}}`},
		{name: "object user", contentType: "application/json", body: `{"data":{"requestContext":{"userId":{}}}}`},
		{name: "boolean user", contentType: "application/json", body: `{"data":{"requestContext":{"userId":true}}}`},
		{name: "zero user", contentType: "application/json", body: `{"data":{"requestContext":{"userId":0}}}`},
		{name: "fractional user", contentType: "application/json", body: `{"data":{"requestContext":{"userId":1.5}}}`},
		{name: "trailing JSON", contentType: "application/json", body: `{"data":{"requestContext":{"userId":1}}} {}`},
		{name: "oversized", contentType: "application/json", body: `{"data":{"requestContext":{"userId":1}}}` + strings.Repeat(" ", (1<<20)+1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			v := &Verifier{endpoints: []endpoint{{region: "US", url: server.URL}}, httpClient: server.Client()}
			result := v.Verify(context.Background(), rawFinding(testToken))
			assert.Equal(t, finding.StatusVerifyError, result.Status)
			assert.NotEqual(t, finding.StatusVerifiedActive, result.Status)
			assert.NotEqual(t, finding.StatusVerifiedInactive, result.Status)
		})
	}
}

func TestVerify_EmptyOrCancelledIsSafe(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	v := &Verifier{endpoints: []endpoint{{region: "US", url: server.URL}}, httpClient: server.Client()}

	for _, token := range []string{"", " \t\r\n"} {
		result := v.Verify(context.Background(), rawFinding(token))
		assert.Equal(t, finding.StatusUnverified, result.Status)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := v.Verify(ctx, rawFinding(testToken))
	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Zero(t, requests.Load())
}

func TestVerificationRequestBudget(t *testing.T) {
	assert.Equal(t, len(officialEndpoints), (&Verifier{}).VerificationRequestBudget())
	assert.Equal(t, 1, (&Verifier{endpoints: []endpoint{{region: "test", url: "https://example.test"}}}).VerificationRequestBudget())
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	assert.Equal(t, detectorID, (&Verifier{}).Type())
}

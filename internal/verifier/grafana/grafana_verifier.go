// Package grafana provides a verifier for Grafana service-account tokens.
// It uses the issuing instance's read-only access-control permissions endpoint.
package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	// instanceURL is either empty or normalized by NewForTrustedInstance. Tests
	// in this package may set it directly to reach a hermetic HTTP server.
	// Repository content and RawFinding.ExtraData must never populate it because
	// doing so would turn verification into an SSRF primitive.
	instanceURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

func init() {
	verifier.Register(&Verifier{})
}

// NewForTrustedInstance constructs a Grafana verifier for an instance origin
// explicitly supplied by the operator. Callers MUST NOT pass a URL extracted
// from scanned repository content. The CLI intentionally exposes this only as
// a command-line flag, not as a project-config or finding field.
func NewForTrustedInstance(instanceURL string) (*Verifier, error) {
	normalized, err := normalizeTrustedInstanceURL(instanceURL)
	if err != nil {
		return nil, err
	}
	return &Verifier{instanceURL: normalized}, nil
}

// WithTrustedInstance implements verifier.TrustedInstanceConfigurer.
func (*Verifier) WithTrustedInstance(instanceURL string) (verifier.Verifier, error) {
	return NewForTrustedInstance(instanceURL)
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
	if strings.TrimSpace(token) == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}
	if v.instanceURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "Grafana instance URL required",
		}
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "grafana",
		Request: httpx.Request{
			URL: v.instanceURL + permissionsPath,
			Header: map[string]string{
				"Accept":        "application/json",
				"Authorization": "Bearer " + token,
			},
		},
		ActiveMessage:       "Grafana API key is active",
		InactiveMessage:     "Grafana API key is invalid or revoked",
		Decode:              decodePermissionsObject,
		RequireCompleteBody: true,
	})
}

func normalizeTrustedInstanceURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid Grafana instance URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("invalid Grafana instance URL: an absolute HTTPS origin is required")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("invalid Grafana instance URL: userinfo, query, and fragment are not allowed")
	}
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return "", fmt.Errorf("invalid Grafana instance URL: a base origin without a path is required")
	}

	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hostname == "" || strings.ContainsAny(hostname, "* \t\r\n") {
		return "", fmt.Errorf("invalid Grafana instance URL: a concrete hostname is required")
	}
	if hostname == "grafana.com" || hostname == "www.grafana.com" {
		return "", fmt.Errorf("invalid Grafana instance URL: the central grafana.com portal is not an issuing instance")
	}
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return "", fmt.Errorf("invalid Grafana instance URL: local targets are not allowed")
	}
	if ip := net.ParseIP(hostname); ip != nil &&
		(!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
		return "", fmt.Errorf("invalid Grafana instance URL: non-public IP targets are not allowed")
	}

	u.Scheme = "https"
	u.Path = ""
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func decodePermissionsObject(body io.Reader) (map[string]string, string, error) {
	decoder := json.NewDecoder(body)
	var permissions map[string]json.RawMessage
	if err := decoder.Decode(&permissions); err != nil {
		return nil, "", fmt.Errorf("invalid Grafana permissions response: %w", err)
	}
	if permissions == nil {
		return nil, "", fmt.Errorf("invalid Grafana permissions response: expected JSON object")
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, "", fmt.Errorf("invalid Grafana permissions response: trailing JSON value")
		}
		return nil, "", fmt.Errorf("invalid Grafana permissions response: %w", err)
	}
	return nil, "", nil
}

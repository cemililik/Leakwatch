package verifier

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// NormalizeTrustedHTTPSOrigin validates an origin explicitly supplied by the
// operator. Scanned repository content must never be passed to this function:
// accepting a finding-derived URL would turn verification into a credential
// exfiltration primitive.
func NormalizeTrustedHTTPSOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("invalid trusted origin: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("invalid trusted origin: an absolute HTTPS origin is required")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("invalid trusted origin: userinfo, query, and fragment are not allowed")
	}
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return "", fmt.Errorf("invalid trusted origin: a base origin without a path is required")
	}
	hostname := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if hostname == "" || strings.ContainsAny(hostname, "* \t\r\n") {
		return "", fmt.Errorf("invalid trusted origin: a concrete hostname is required")
	}
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return "", fmt.Errorf("invalid trusted origin: local targets are not allowed")
	}
	if _, parseErr := netip.ParseAddr(hostname); parseErr == nil {
		return "", fmt.Errorf("invalid trusted origin: IP-literal targets are not allowed")
	}
	port := u.Port()
	u.Host = hostname
	if port != "" {
		u.Host += ":" + port
	}
	u.Scheme = "https"
	u.Path = ""
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

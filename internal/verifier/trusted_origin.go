package verifier

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeTrustedHTTPSOrigin validates an origin explicitly supplied by the
// operator. Scanned repository content must never be passed to this function:
// accepting a finding-derived URL would turn verification into a credential
// exfiltration primitive.
func NormalizeTrustedHTTPSOrigin(raw string) (string, error) {
	u, err := parseTrustedHTTPSOrigin(raw)
	if err != nil {
		return "", err
	}
	hostname, err := trustedOriginHostname(u)
	if err != nil {
		return "", err
	}
	u.Host = hostnameWithOptionalPort(hostname, u.Port())
	u.Scheme = "https"
	u.Path = ""
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func parseTrustedHTTPSOrigin(raw string) (*url.URL, error) {
	u, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid trusted origin: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("invalid trusted origin: an absolute HTTPS origin is required")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("invalid trusted origin: userinfo, query, and fragment are not allowed")
	}
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return nil, fmt.Errorf("invalid trusted origin: a base origin without a path is required")
	}
	return u, nil
}

func trustedOriginHostname(u *url.URL) (string, error) {
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
	if looksLikeNumericHost(hostname) {
		return "", fmt.Errorf("invalid trusted origin: non-canonical numeric targets are not allowed")
	}
	if err := validateTrustedOriginPort(u.Port()); err != nil {
		return "", err
	}
	return hostname, nil
}

func validateTrustedOriginPort(port string) error {
	if port != "" {
		value, portErr := strconv.ParseUint(port, 10, 16)
		if portErr != nil || value == 0 {
			return fmt.Errorf("invalid trusted origin: port must be between 1 and 65535")
		}
	}
	return nil
}

func hostnameWithOptionalPort(hostname, port string) string {
	if port != "" {
		return hostname + ":" + port
	}
	return hostname
}

func looksLikeNumericHost(hostname string) bool {
	parts := strings.Split(hostname, ".")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		digits := part
		base := byte(10)
		if strings.HasPrefix(part, "0x") {
			digits = part[2:]
			base = 16
		}
		if digits == "" {
			return false
		}
		for _, r := range digits {
			if r >= '0' && r <= '9' {
				continue
			}
			if base == 16 && r >= 'a' && r <= 'f' {
				continue
			}
			return false
		}
	}
	return true
}

package detector

import (
	"bytes"
	"net/url"
	"strings"
)

// redactMask is the fixed mask placed in front of the revealed suffix.
const redactMask = "****"

// revealedSuffixLen is the maximum number of trailing characters that Redact
// leaves visible. It is intentionally small so that a redacted value carries
// just enough information to correlate findings without exposing usable secret
// material.
const revealedSuffixLen = 4

// Redact returns a uniformly redacted representation of a secret value.
//
// The scheme is deliberately simple and consistent across every detector:
// reveal at most the last revealedSuffixLen characters of the value and never
// any leading body characters. The result is always "****" followed by the
// revealed suffix, e.g. Redact("AKIA1234567890ABCD") == "****ABCD".
//
// Detectors that match a value behind a FIXED literal prefix (for example a
// regex anchored on "sk-ant-") may prepend that constant prefix themselves;
// the prefix is part of the pattern, not secret-derived, so it leaks nothing.
// When in doubt prefer the bare "****"+suffix form.
//
// Redact never reveals the full value: if the value is shorter than or equal to
// revealedSuffixLen the entire value is masked. The suffix is measured and
// sliced in runes, not bytes, so the revealed portion is always valid UTF-8
// even when the value contains multi-byte characters near its end.
func Redact(value string) string {
	runes := []rune(value)
	if len(runes) <= revealedSuffixLen {
		return redactMask
	}
	return redactMask + string(runes[len(runes)-revealedSuffixLen:])
}

// RedactBytes is the []byte convenience wrapper around Redact. It does not log,
// store, or otherwise retain the input beyond computing the redacted suffix.
func RedactBytes(value []byte) string {
	return Redact(string(value))
}

// RedactURLPassword redacts the password component of a URL-shaped credential
// string (e.g. "amqp://user:pass@host:5672/vhost"), keeping the scheme,
// username, host and path visible for correlation while masking the secret.
//
// It is fail-safe: it NEVER returns the raw input unmodified. If the value
// cannot be parsed as a URL, or net/url finds no userinfo component in the
// authority (a credential may still be embedded elsewhere in the matched text,
// e.g. in the path or query, since detector regexes typically only exclude
// whitespace and quotes), the value is masked down to at most the scheme
// rather than risk echoing a cleartext credential.
func RedactURLPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactMask
	}
	if u.User == nil {
		if u.Scheme == "" {
			return redactMask
		}
		return u.Scheme + "://" + redactMask
	}
	username := u.User.Username()
	u.User = nil
	return u.Scheme + "://" + username + ":" + redactMask + "@" + u.Host + u.RequestURI()
}

// HasAnyKeyword reports whether data contains any of the given keywords,
// matched case-insensitively. It is intended for detectors that gate a broad
// regex behind a context check confirming a domain-specific keyword is
// present nearby, so callers do not need to hand-enumerate case variants.
func HasAnyKeyword(data []byte, keywords ...string) bool {
	lower := bytes.ToLower(data)
	for _, kw := range keywords {
		if bytes.Contains(lower, []byte(strings.ToLower(kw))) {
			return true
		}
	}
	return false
}

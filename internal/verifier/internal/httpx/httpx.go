// Package httpx provides a shared, security-hardened HTTP client and helpers
// for use by secret verifiers.
//
// It is intentionally placed under internal/verifier/internal so that it can
// only be imported by packages within internal/verifier.
//
// Security rationale:
//
//   - Verifiers send provider credentials in custom headers (for example
//     x-api-key, PRIVATE-TOKEN, DD-API-KEY) or embedded in the request URL
//     (for example Telegram and Infura). On a cross-domain 3xx redirect, the
//     Go standard library strips the Authorization header but NOT custom
//     headers, and it re-sends the full URL — which would leak the credential
//     to an attacker-controlled redirect target. To prevent this, the shared
//     client does NOT follow redirects: it returns the 3xx response so the
//     verifier can decide how to map it (see IsRedirect).
//
//   - Response bodies are read through a bounded reader (LimitReader) so a
//     malicious or misbehaving endpoint cannot exhaust memory.
//
//   - The client does NOT set an http.Client.Timeout wall-clock ceiling.
//     Request duration is governed solely by the per-request context deadline
//     the verification engine applies (derived from the operator-configured
//     verification.timeout). A client-level Timeout would silently cap that
//     configured value and cannot be reconciled with it here, so it is omitted;
//     callers MUST pass a context with a deadline.
//
//   - The client asserts an explicit TLS 1.2 minimum version rather than
//     relying on the crypto/tls default, as defense-in-depth and
//     self-documentation.
//
// This helper deliberately does NOT implement retry, backoff, or per-provider
// rate limiting. Those concerns are handled (or deferred) elsewhere; keeping
// this package focused on transport safety.
package httpx

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// MaxBodyBytes is the maximum number of response-body bytes a verifier reads.
// It caps memory usage when decoding provider responses. 1 MiB is far larger
// than any legitimate verification response.
const MaxBodyBytes int64 = 1 << 20

var (
	clientOnce   sync.Once
	sharedClient *http.Client
)

// noRedirect instructs the HTTP client to return the most recent response
// (the 3xx) instead of following the redirect. This prevents credentials in
// custom headers or in the request URL from being re-sent to a redirect
// target, which the standard library would otherwise do for non-Authorization
// headers.
func noRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// Client returns the shared, security-hardened HTTP client.
//
// The returned client is safe for concurrent use and is shared across all
// verifiers. Callers MUST NOT mutate it. Tests that need to point a verifier
// at a stub server should inject their own *http.Client through the verifier's
// test seam instead of mutating this client.
func Client() *http.Client {
	clientOnce.Do(func() {
		// Clone the default transport so we benefit from connection pooling
		// and environment proxy settings without sharing mutable state with
		// http.DefaultTransport.
		transport := http.DefaultTransport
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			cloned := dt.Clone()
			// Assert an explicit TLS floor instead of relying on the crypto/tls
			// default, both as defense-in-depth against a future stdlib default
			// change and as self-documentation.
			if cloned.TLSClientConfig == nil {
				cloned.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			} else {
				cloned.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
			transport = cloned
		}
		sharedClient = &http.Client{
			Transport:     transport,
			CheckRedirect: noRedirect,
			// No Timeout: request duration is bounded by the per-request context
			// deadline the verification engine applies (see package doc).
		}
	})
	return sharedClient
}

// LimitReader wraps r so that at most MaxBodyBytes are read from it. Verifiers
// should decode response bodies through this reader (for example
// json.NewDecoder(httpx.LimitReader(resp.Body))) to bound memory usage.
func LimitReader(r io.Reader) io.Reader {
	return io.LimitReader(r, MaxBodyBytes)
}

// IsRedirect reports whether the given HTTP status code is a 3xx redirect.
//
// Because Client does not follow redirects, verifiers observe 3xx responses
// directly. A redirect from an API endpoint generally means the credential
// context is wrong (for example a wrong host or a login redirect), so it should
// NOT be treated as a successful verification.
func IsRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

// RedactError returns err.Error() with every occurrence of secret replaced by
// "[REDACTED]".
//
// Transport errors from net/http wrap a *url.Error whose message embeds the
// full request URL. When a verifier places a credential in the request URL (for
// example Telegram and Infura embed the token in the path, and Teams uses the
// webhook URL itself), a DNS, TLS, or proxy failure would otherwise echo that
// credential into logs and the returned VerificationResult.Message. Callers MUST
// route such error text through this helper before logging or returning it.
//
// If secret is empty the original message is returned unchanged, since an empty
// match would otherwise corrupt the string. The returned text is safe to log.
func RedactError(err error, secret string) string {
	if err == nil {
		return ""
	}
	return redactText(err.Error(), secret)
}

func redactText(msg, secret string) string {
	if secret == "" {
		return msg
	}
	// Redact the raw secret and its URL-encoded representations. A credential
	// embedded in a request URL may be percent-encoded by net/url before it
	// surfaces inside a transport error's message, so matching only the raw
	// value could silently miss a transformed occurrence.
	for _, form := range redactionForms(secret) {
		msg = strings.ReplaceAll(msg, form, "[REDACTED]")
	}
	return msg
}

// redactionForms returns the distinct non-empty textual forms a secret may take
// in error text: the raw value plus its path- and query-escaped encodings.
func redactionForms(secret string) []string {
	candidates := []string{secret, url.PathEscape(secret), url.QueryEscape(secret)}
	seen := make(map[string]struct{}, len(candidates))
	forms := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		forms = append(forms, c)
	}
	return forms
}

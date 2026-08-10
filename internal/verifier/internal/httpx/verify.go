package httpx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// userAgent is the User-Agent every verifier request carries.
const userAgent = "leakwatch-verifier"

// Request describes the single HTTP request a verifier sends to a provider.
// VerifyToken builds and performs it through the shared, security-hardened
// client, so callers only declare what differs between providers.
type Request struct {
	// Method defaults to GET when empty.
	Method string
	// URL is the fully-formed request URL.
	URL string
	// Body, when non-nil, is sent as the request body.
	Body []byte
	// Header holds additional request headers (for example the provider auth
	// header). User-Agent is always set automatically.
	Header map[string]string
	// BasicAuthUser and BasicAuthPass, when either is non-empty, set HTTP Basic
	// auth on the request (req.SetBasicAuth).
	BasicAuthUser string
	BasicAuthPass string
}

// DecodeFunc inspects an active-status (typically 200) response body. It returns
// the ExtraData to attach to a verified-active result. When it returns a
// non-empty downgradeMessage, VerifyToken instead reports verified-inactive with
// that message — used by APIs that return 200 with an "ok":false / "valid":false
// body. A non-nil error yields StatusVerifyError.
//
// The reader passed to a DecodeFunc is already bounded by LimitReader.
type DecodeFunc func(body io.Reader) (extra map[string]string, downgradeMessage string, err error)

// TokenSpec describes a standard single-request token verification: the request
// to send and how each response status maps to a VerificationResult.
//
// The shared flow — User-Agent, no-redirect handling, bounded body, error
// redaction, and the canonical "unexpected status code" / "failed to decode"
// results — lives in VerifyToken, so each verifier declares only what is
// provider-specific. This keeps the ~50 verifier packages free of the
// near-identical request/response boilerplate they previously duplicated.
type TokenSpec struct {
	// Name identifies the verifier in structured logs, for example "openai".
	Name string

	// Request is the provider request to send.
	Request Request

	// Redact, when non-empty, is stripped from any error text before it is
	// logged or returned. Set it to the secret when the credential appears in
	// the request URL (token-in-path verifiers such as telegram and infura).
	Redact string

	// ActiveStatuses are the HTTP status codes mapped to verified-active.
	// Defaults to {200} when nil.
	ActiveStatuses []int

	// InactiveStatuses are the HTTP status codes mapped to verified-inactive.
	// Defaults to {401} when nil. Pass a non-nil empty slice ([]int{}) for
	// verifiers that decide inactive solely from the response body, so that no
	// status code maps to inactive (any unexpected code is a verify error).
	InactiveStatuses []int

	// ActiveMessage and InactiveMessage are the result messages for an
	// active / inactive outcome.
	ActiveMessage   string
	InactiveMessage string

	// ActiveExtra is attached to an active result when Decode is nil. Use it for
	// verifiers that report static ExtraData (for example a key type) without
	// reading the response body. Ignored when Decode is set.
	ActiveExtra map[string]string

	// Decode, when non-nil, is invoked on an active-status response body to
	// extract ExtraData (and optionally downgrade the result). When nil, an
	// active-status response yields a bare active result without reading the body.
	Decode DecodeFunc

	// RequireCompleteBody reads the full active response through a strict
	// MaxBodyBytes+1 bound before Decode runs. Responses over the bound are
	// rejected instead of letting a truncated prefix appear valid.
	RequireCompleteBody bool
}

// BaseURL returns override when it is non-empty, otherwise fallback. Verifiers
// use it to honor a test-injected API base URL while defaulting to the real one.
func BaseURL(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}

// VerifyToken performs the verification described by spec and maps the response
// to a VerificationResult. The token is checked for emptiness first (an empty
// credential is StatusUnverified, never an HTTP call). client may be nil, in
// which case the shared hardened Client is used.
func VerifyToken(ctx context.Context, client *http.Client, token string, spec TokenSpec) finding.VerificationResult {
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	resp, errResult := spec.send(ctx, client)
	if errResult != nil {
		return *errResult
	}
	defer func() {
		// Drain the remaining body (bounded by MaxBodyBytes so a misbehaving
		// endpoint cannot exhaust memory) before closing, so the underlying
		// connection can be returned to the shared client's keep-alive pool
		// instead of being discarded.
		_, _ = io.Copy(io.Discard, LimitReader(resp.Body))
		_ = resp.Body.Close()
	}()

	code := resp.StatusCode
	switch {
	case containsStatus(spec.activeStatuses(), code):
		return spec.handleActive(ctx, resp.Body)
	case containsStatus(spec.inactiveStatuses(), code):
		slog.DebugContext(ctx, spec.Name+" verifier: secret is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: spec.InactiveMessage,
		}
	case code == http.StatusTooManyRequests:
		// A provider-side rate limit must be distinguishable from a genuine
		// verification bug: report an actionable message rather than a generic
		// "unexpected status code".
		return RateLimited(ctx, spec.Name, resp.Header.Get("Retry-After"))
	default:
		return UnexpectedStatus(ctx, spec.Name, code)
	}
}

// send builds and performs the request, applying the shared safety policy. On a
// build, transport, or redirect failure it returns a non-nil result describing
// the StatusVerifyError; otherwise it returns the response (caller closes Body).
func (spec TokenSpec) send(ctx context.Context, client *http.Client) (*http.Response, *finding.VerificationResult) {
	method := spec.Request.Method
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader
	if spec.Request.Body != nil {
		body = bytes.NewReader(spec.Request.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, spec.Request.URL, body)
	if err != nil {
		safeErr := RedactError(err, spec.Redact)
		slog.ErrorContext(ctx, spec.Name+" verifier: failed to create request", slog.String("error", safeErr))
		return nil, &finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %s", safeErr),
		}
	}

	for k, val := range spec.Request.Header {
		req.Header.Set(k, val)
	}
	if spec.Request.BasicAuthUser != "" || spec.Request.BasicAuthPass != "" {
		req.SetBasicAuth(spec.Request.BasicAuthUser, spec.Request.BasicAuthPass)
	}
	req.Header.Set("User-Agent", userAgent)

	if client == nil {
		client = Client()
	}

	resp, err := client.Do(req)
	if err != nil {
		safeErr := RedactError(err, spec.Redact)
		slog.ErrorContext(ctx, spec.Name+" verifier: request failed", slog.String("error", safeErr))
		return nil, &finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %s", safeErr),
		}
	}

	// The shared client does not follow redirects: a 3xx from an API endpoint
	// means the credential context is wrong, never that the secret is active.
	if IsRedirect(resp.StatusCode) {
		_ = resp.Body.Close()
		return nil, &finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected redirect (status %d)", resp.StatusCode),
		}
	}

	return resp, nil
}

// handleActive maps an active-status response to a result, decoding the body for
// ExtraData (and any downgrade) when a DecodeFunc is configured.
func (spec TokenSpec) handleActive(ctx context.Context, body io.Reader) finding.VerificationResult {
	if spec.Decode == nil {
		slog.InfoContext(ctx, spec.Name+" verifier: secret is active")
		return finding.VerificationResult{
			Status:    finding.StatusVerifiedActive,
			Message:   spec.ActiveMessage,
			ExtraData: spec.ActiveExtra,
		}
	}

	decodeBody := LimitReader(body)
	if spec.RequireCompleteBody {
		contents, err := io.ReadAll(io.LimitReader(body, MaxBodyBytes+1))
		if err != nil {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: fmt.Sprintf("200 OK but failed to read response body: %v", err),
			}
		}
		if int64(len(contents)) > MaxBodyBytes {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: fmt.Sprintf("200 OK but response body exceeds %d bytes", MaxBodyBytes),
			}
		}
		decodeBody = bytes.NewReader(contents)
	}

	extra, downgrade, err := spec.Decode(decodeBody)
	if err != nil {
		slog.ErrorContext(ctx, spec.Name+" verifier: failed to decode response", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("200 OK but failed to decode response body: %v", err),
		}
	}

	if downgrade != "" {
		slog.DebugContext(ctx, spec.Name+" verifier: secret reported inactive by response body")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: downgrade,
		}
	}

	slog.InfoContext(ctx, spec.Name+" verifier: secret is active")
	return finding.VerificationResult{
		Status:    finding.StatusVerifiedActive,
		Message:   spec.ActiveMessage,
		ExtraData: extra,
	}
}

// RateLimited returns a distinguished StatusVerifyError result for an HTTP 429
// (Too Many Requests) response, so a provider-side rate limit is never conflated
// with a genuine verification bug or an inactive secret. Only a syntactically
// valid delta-seconds or HTTP-date Retry-After value is emitted; arbitrary
// provider-controlled header text is never copied into logs or results.
func RateLimited(ctx context.Context, name, retryAfter string) finding.VerificationResult {
	retryAfter = canonicalRetryAfter(retryAfter)
	msg := "rate limited by provider (HTTP 429), retry later"
	if retryAfter != "" {
		msg = fmt.Sprintf("%s (Retry-After: %s)", msg, retryAfter)
	}
	slog.WarnContext(ctx, name+" verifier: rate limited by provider",
		slog.String("retry_after", retryAfter))
	return finding.VerificationResult{
		Status:  finding.StatusVerifyError,
		Message: msg,
	}
}

func canonicalRetryAfter(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		return strconv.FormatUint(seconds, 10)
	}
	if retryAt, err := http.ParseTime(value); err == nil {
		return retryAt.UTC().Format(http.TimeFormat)
	}
	return ""
}

// UnexpectedStatus returns the canonical StatusVerifyError result for a response
// status code that a verifier does not recognize.
func UnexpectedStatus(ctx context.Context, name string, code int) finding.VerificationResult {
	slog.ErrorContext(ctx, name+" verifier: unexpected status code", slog.Int("status_code", code))
	return finding.VerificationResult{
		Status:  finding.StatusVerifyError,
		Message: fmt.Sprintf("unexpected status code: %d", code),
	}
}

func (spec TokenSpec) activeStatuses() []int {
	if spec.ActiveStatuses == nil {
		return []int{http.StatusOK}
	}
	return spec.ActiveStatuses
}

func (spec TokenSpec) inactiveStatuses() []int {
	if spec.InactiveStatuses == nil {
		return []int{http.StatusUnauthorized}
	}
	return spec.InactiveStatuses
}

func containsStatus(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

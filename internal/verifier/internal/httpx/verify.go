package httpx

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// userAgent is the User-Agent every verifier request carries.
const userAgent = "leakwatch-verifier"

const (
	max429Attempts  = 2
	max429RetryWait = 2 * time.Second
	maxJitterRatio  = 0.10
)

type retryGateKey struct{}

// RetryGate is installed by the verification engine and admits one retry at
// its actual send point through both the provider and global rate limiters.
// Returning a non-nil result rejects the retry without sending it.
type RetryGate func() *finding.VerificationResult

// WithRetryGate returns a child context carrying the engine-owned admission
// gate used only for an HTTP 429 retry. The initial request remains admitted by
// the engine immediately before invoking the verifier.
func WithRetryGate(ctx context.Context, gate RetryGate) context.Context {
	if gate == nil {
		return ctx
	}
	return context.WithValue(ctx, retryGateKey{}, gate)
}

// Request describes the logical HTTP probe a verifier sends to a provider.
// VerifyToken builds and performs it through the shared, security-hardened
// client; a safe GET/HEAD probe may be replayed once after a bounded HTTP 429.
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

// InactiveDecodeFunc validates that an inactive-status response is definitive
// for the provider. A nil error permits verified-inactive; an error keeps the
// outcome fail-conservative as StatusVerifyError. It is intended for providers
// whose 401 class also includes challenges such as DPoP that do not prove a
// credential is invalid.
type InactiveDecodeFunc func(body io.Reader) error

// TokenSpec describes a standard token verification probe: the request to send
// and how each response status maps to a VerificationResult.
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

	// Redact is an optional additional sensitive value stripped from error text.
	// VerifyToken always redacts its token argument; use this field only when a
	// request contains another credential-bearing representation.
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

	// DecodeInactive, when non-nil, must positively validate an inactive-status
	// response body before the credential is classified as inactive. The body is
	// read completely through the same strict size bound used for active bodies.
	DecodeInactive InactiveDecodeFunc

	// RequireCompleteBody reads the full active response through a strict
	// MaxBodyBytes+1 bound before Decode runs. Responses over the bound are
	// rejected instead of letting a truncated prefix appear valid.
	RequireCompleteBody bool

	// RequireJSONContentType rejects an active response unless its media type is
	// application/json or an application/*+json subtype. The raw header is never
	// reflected into logs or result messages.
	RequireJSONContentType bool
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

	for attempt := 1; attempt <= max429Attempts; attempt++ {
		resp, errResult := spec.send(ctx, client, token)
		if errResult != nil {
			return *errResult
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < max429Attempts && spec.retrySafe() {
			rawRetryAfter := resp.Header.Get("Retry-After")
			delay, ok := retryAfterDelay(rawRetryAfter, time.Now())
			closeResponse(resp)
			if ok && delay <= max429RetryWait {
				delay = addRetryJitter(delay, max429RetryWait, retryJitterUnit())
				if retryFitsContext(ctx, delay) {
					slog.DebugContext(ctx, spec.Name+" verifier: scheduling bounded HTTP 429 retry",
						slog.Int("next_attempt", attempt+1),
						slog.Int("max_attempts", max429Attempts),
						slog.Duration("retry_wait", delay),
						slog.Duration("max_total_wait", max429RetryWait),
					)
					if result := waitForRetry(ctx, spec.Name, delay); result != nil {
						return *result
					}
					if gate, _ := ctx.Value(retryGateKey{}).(RetryGate); gate != nil {
						if rejection := gate(); rejection != nil {
							return *rejection
						}
					}
					continue
				}
			}
			slog.DebugContext(ctx, spec.Name+" verifier: bounded HTTP 429 retry skipped",
				slog.Int("attempt", attempt),
				slog.Int("max_attempts", max429Attempts),
				slog.Duration("max_total_wait", max429RetryWait),
			)
			return RateLimited(ctx, spec.Name, rawRetryAfter)
		}

		return func() finding.VerificationResult {
			// Decode callbacks are provider-specific code. Preserve response-body
			// cleanup even if one panics and the outer verification engine recovers.
			defer closeResponse(resp)
			return spec.handleResponse(ctx, resp)
		}()
	}

	return finding.VerificationResult{
		Status:  finding.StatusVerifyError,
		Message: "bounded verification attempts exhausted",
	}
}

func (spec TokenSpec) handleResponse(ctx context.Context, resp *http.Response) finding.VerificationResult {
	code := resp.StatusCode
	switch {
	case containsStatus(spec.activeStatuses(), code):
		if spec.RequireJSONContentType && !isJSONContentType(resp.Header.Get("Content-Type")) {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: "200 OK but response Content-Type is not JSON",
			}
		}
		return spec.handleActive(ctx, resp.Body)
	case containsStatus(spec.inactiveStatuses(), code):
		return spec.handleInactive(ctx, resp)
	case code == http.StatusTooManyRequests:
		// A provider-side rate limit must be distinguishable from a genuine
		// verification bug: report an actionable message rather than a generic
		// "unexpected status code".
		return RateLimited(ctx, spec.Name, resp.Header.Get("Retry-After"))
	default:
		return UnexpectedStatus(ctx, spec.Name, code)
	}
}

func (spec TokenSpec) retrySafe() bool {
	method := strings.ToUpper(strings.TrimSpace(spec.Request.Method))
	if method == "" {
		method = http.MethodGet
	}
	return method == http.MethodGet || method == http.MethodHead
}

func retryAfterDelay(raw string, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds > uint64(max429RetryWait/time.Second) {
			return max429RetryWait + time.Nanosecond, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := retryAt.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

func addRetryJitter(base, max time.Duration, unit float64) time.Duration {
	if base <= 0 || max <= base {
		return base
	}
	if unit < 0 {
		unit = 0
	}
	if unit > 1 {
		unit = 1
	}
	jitter := time.Duration(float64(base) * maxJitterRatio * unit)
	if base+jitter > max {
		return max
	}
	return base + jitter
}

func retryJitterUnit() float64 {
	var random [8]byte
	if _, err := cryptorand.Read(random[:]); err != nil {
		// Jitter improves herd behavior but is not required for correctness. A
		// secure-random failure therefore falls back to the provider's exact wait
		// instead of introducing a weak pseudo-random source.
		return 0
	}
	const precisionBits = 53
	value := binary.LittleEndian.Uint64(random[:]) >> (64 - precisionBits)
	return float64(value) / float64((uint64(1)<<precisionBits)-1)
}

func retryFitsContext(ctx context.Context, delay time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Add(delay).Before(deadline)
}

func waitForRetry(ctx context.Context, name string, delay time.Duration) *finding.VerificationResult {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		slog.DebugContext(ctx, name+" verifier: HTTP 429 retry cancelled",
			slog.String("reason", ctx.Err().Error()))
		return &finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: "rate-limit retry cancelled: " + ctx.Err().Error(),
		}
	}
}

func closeResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	// Drain only a bounded amount before closing so keep-alive can be reused
	// without trusting a provider-controlled response size.
	_, _ = io.Copy(io.Discard, LimitReader(resp.Body))
	_ = resp.Body.Close()
}

func isJSONContentType(header string) bool {
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" ||
		(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

// send builds and performs the request, applying the shared safety policy. On a
// build, transport, or redirect failure it returns a non-nil result describing
// the StatusVerifyError; otherwise it returns the response (caller closes Body).
func (spec TokenSpec) send(ctx context.Context, client *http.Client, token string) (*http.Response, *finding.VerificationResult) {
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
		safeErr := redactTransportError(err, spec.redactionSecrets(token)...)
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
		safeErr := redactTransportError(err, spec.redactionSecrets(token)...)
		slog.ErrorContext(ctx, spec.Name+" verifier: request failed", slog.String("error", safeErr))
		return nil, &finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %s", safeErr),
		}
	}

	// The shared client does not follow redirects: a 3xx from an API endpoint
	// means the credential context is wrong, never that the secret is active.
	if IsRedirect(resp.StatusCode) {
		closeResponse(resp)
		return nil, &finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected redirect (status %d)", resp.StatusCode),
		}
	}

	return resp, nil
}

func (spec TokenSpec) redactionSecrets(token string) []string {
	secrets := []string{token, spec.Redact}
	if spec.Request.BasicAuthUser != "" || spec.Request.BasicAuthPass != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(
			spec.Request.BasicAuthUser + ":" + spec.Request.BasicAuthPass,
		))
		secrets = append(secrets, spec.Request.BasicAuthUser, spec.Request.BasicAuthPass, encoded)
	}
	return secrets
}

func redactTransportError(err error, secrets ...string) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	for _, secret := range secrets {
		message = redactText(message, secret)
	}
	return message
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

func (spec TokenSpec) handleInactive(ctx context.Context, resp *http.Response) finding.VerificationResult {
	if spec.DecodeInactive != nil {
		if spec.RequireJSONContentType && !isJSONContentType(resp.Header.Get("Content-Type")) {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: fmt.Sprintf("HTTP %d inactive response Content-Type is not JSON", resp.StatusCode),
			}
		}
		contents, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
		if err != nil {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: fmt.Sprintf("HTTP %d but failed to read response body: %v", resp.StatusCode, err),
			}
		}
		if int64(len(contents)) > MaxBodyBytes {
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: fmt.Sprintf("HTTP %d but response body exceeds %d bytes", resp.StatusCode, MaxBodyBytes),
			}
		}
		if err := spec.DecodeInactive(bytes.NewReader(contents)); err != nil {
			slog.DebugContext(ctx, spec.Name+" verifier: inactive response was not definitive")
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: fmt.Sprintf("HTTP %d did not definitively prove the secret inactive", resp.StatusCode),
			}
		}
	}

	slog.DebugContext(ctx, spec.Name+" verifier: secret is inactive")
	return finding.VerificationResult{
		Status:  finding.StatusVerifiedInactive,
		Message: spec.InactiveMessage,
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

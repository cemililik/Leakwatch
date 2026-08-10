package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// DefaultTimeout is the default timeout for one finding's complete verification
// operation, including any bounded provider-region fallback requests.
const DefaultTimeout = 10 * time.Second

// DefaultConcurrency is the default number of concurrent verification workers.
const DefaultConcurrency = 4

// DefaultRateLimit is the default maximum verification requests per second.
const DefaultRateLimit = 10.0

// maxVerificationRequestBudget prevents a buggy verifier from reserving an
// unbounded number of limiter tokens for one finding.
const maxVerificationRequestBudget = 8

// Config holds the verification engine configuration.
type Config struct {
	// Enabled controls whether verification is performed at all.
	Enabled bool

	// Timeout is the maximum duration for one finding's complete verification
	// operation, including bounded provider-region fallback requests.
	Timeout time.Duration

	// Concurrency is the number of concurrent verification workers.
	Concurrency int

	// RateLimit is the maximum verification requests per second.
	//
	// The rate applies both as a per-detector budget (each distinct detector ID
	// gets its own limiter of this rate) and as a global ceiling shared across
	// all providers, so one high-volume detector type cannot starve the
	// verification of unrelated findings in the same run.
	RateLimit float64
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() Config {
	return Config{
		Enabled:     true,
		Timeout:     DefaultTimeout,
		Concurrency: DefaultConcurrency,
		RateLimit:   DefaultRateLimit,
	}
}

// Engine orchestrates concurrent secret verification with rate limiting.
// It maps findings to the appropriate verifier by detector ID and applies
// per-finding operation timeouts and global rate limiting.
type Engine struct {
	verifiers map[string]Verifier

	// rateLimiter is the global ceiling shared across every provider.
	rateLimiter *rate.Limiter

	// perDetector holds a lazily-created rate limiter per detector ID so one
	// high-volume provider cannot exhaust the token budget of another. Guarded
	// by perDetectorMu. rateLimit/burst are captured so new limiters match the
	// configured rate.
	perDetectorMu sync.Mutex
	perDetector   map[string]*rate.Limiter
	rateLimit     rate.Limit
	burst         int

	timeout     time.Duration
	concurrency int
	enabled     bool
}

// NewEngine creates a verification engine from the given config and verifier list.
// If cfg.Enabled is false, the engine will pass through findings unmodified.
func NewEngine(cfg Config, vs []Verifier) *Engine {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}

	vMap := make(map[string]Verifier, len(vs))
	for i, v := range vs {
		if isNilVerifier(v) {
			slog.Error("nil verifier ignored while building verification engine", "index", i)
			continue
		}
		id, ok := safeVerifierType(v)
		if !ok || id == "" {
			slog.Error("invalid verifier ignored while building verification engine", "index", i)
			continue
		}
		if _, exists := vMap[id]; exists {
			// Unlike registry.Register (which panics), NewEngine tolerates a
			// duplicate Type() but must not lose it silently: warn so the
			// capability loss is observable.
			slog.Warn(
				"duplicate verifier type; later verifier overwrites earlier",
				"verifier_type", id,
			)
		}
		vMap[id] = v
	}

	burst := int(cfg.RateLimit)
	if burst < 1 {
		burst = 1
	}

	return &Engine{
		verifiers:   vMap,
		rateLimiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), burst),
		perDetector: make(map[string]*rate.Limiter),
		rateLimit:   rate.Limit(cfg.RateLimit),
		burst:       burst,
		timeout:     cfg.Timeout,
		concurrency: cfg.Concurrency,
		enabled:     cfg.Enabled,
	}
}

func safeVerifierType(v Verifier) (id string, ok bool) {
	defer func() {
		if recover() != nil {
			// Type implementations are not allowed to crash engine construction;
			// the recovered value may contain sensitive data and is discarded.
			id = ""
			ok = false
		}
	}()
	return v.Type(), true
}

// limiterFor returns the per-detector rate limiter for detectorID, creating it
// on first use. Each detector gets an independent budget at the configured rate.
func (e *Engine) limiterFor(detectorID string) *rate.Limiter {
	e.perDetectorMu.Lock()
	defer e.perDetectorMu.Unlock()
	l, ok := e.perDetector[detectorID]
	if !ok {
		l = rate.NewLimiter(e.rateLimit, e.burst)
		e.perDetector[detectorID] = l
	}
	return l
}

// VerifyAll verifies all findings concurrently and returns updated findings.
// Findings without a matching verifier are returned with StatusUnverified.
// If the engine is disabled, all findings are returned as-is.
//
// Concurrency safety: each worker writes to a distinct index in the results
// slice. In Go, distinct-index writes to a pre-allocated slice are safe
// without additional synchronization because they target non-overlapping
// memory locations.
func (e *Engine) VerifyAll(ctx context.Context, pairs []VerifyPair) []finding.Finding {
	results := make([]finding.Finding, len(pairs))

	if !e.enabled {
		slog.Debug(
			"verification disabled, skipping all verifications",
			"count", len(pairs),
		)
		for i, p := range pairs {
			results[i] = p.Finding
		}
		return results
	}

	type indexedPair struct {
		index int
		pair  VerifyPair
	}

	// Invariant (not runtime-checked): each pair is dispatched with a unique
	// index (0..len-1) by the job feeder below, so no two workers ever write to
	// the same results slot. This is what makes the unsynchronized indexed-slice
	// writes in the worker loop safe.

	// Use a bounded channel buffer to avoid allocating memory proportional to
	// len(pairs). A separate goroutine feeds jobs so workers can start immediately.
	jobs := make(chan indexedPair, e.concurrency)
	var wg sync.WaitGroup

	// Start worker pool.
	workerCount := e.concurrency
	if workerCount > len(pairs) {
		workerCount = len(pairs)
	}
	if workerCount == 0 {
		return results
	}

	wg.Add(workerCount)
	for w := 0; w < workerCount; w++ {
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results[ip.index] = e.verifySingle(ctx, ip.pair)
			}
		}()
	}

	// Feed jobs in a separate goroutine to avoid blocking when buffer is full.
	go func() {
		defer close(jobs)
		for i, p := range pairs {
			jobs <- indexedPair{index: i, pair: p}
		}
	}()

	wg.Wait()
	return results
}

// verifySingle verifies a single finding, applying rate limiting and timeout.
func (e *Engine) verifySingle(ctx context.Context, pair VerifyPair) finding.Finding {
	f := pair.Finding

	v, ok := e.verifiers[pair.Raw.DetectorID]
	if !ok {
		slog.Debug(
			"no verifier registered for detector, skipping",
			"detector_id", pair.Raw.DetectorID,
		)
		return f
	}

	// Apply one timeout to the complete provider verification operation,
	// including rate-limiter admission and any bounded regional fallback.
	verifyCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	slog.Debug(
		"verifying finding",
		"detector_id", pair.Raw.DetectorID,
		"redacted", pair.Raw.Redacted,
	)

	var result finding.VerificationResult
	if gated, ok := v.(RequestGatedVerifier); ok {
		requestBudget, err := safeVerificationRequestBudget(gated)
		if err != nil {
			f.Verification = finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: "verifier declared an invalid request budget",
			}
			return f
		}
		result = e.safeVerifyWithRequestGate(
			verifyCtx,
			gated,
			pair.Raw,
			e.boundedRequestGate(verifyCtx, pair.Raw.DetectorID, requestBudget),
		)
	} else {
		// Single-request verifiers are admitted immediately before Verify. Their
		// existing contract permits at most one provider request.
		if res := e.waitRateLimit(verifyCtx, pair.Raw.DetectorID); res != nil {
			f.Verification = *res
			return f
		}
		result = e.safeVerify(verifyCtx, v, pair.Raw)
	}
	f.Verification = result

	slog.Debug(
		"verification complete",
		"detector_id", pair.Raw.DetectorID,
		"status", result.Status.String(),
	)

	return f
}

// waitRateLimit blocks until both the per-detector and global rate limiters
// admit a request, honoring ctx cancellation. It returns a non-nil result
// describing a StatusVerifyError when the context is cancelled while waiting,
// and nil when the request may proceed.

func (e *Engine) waitRateLimit(ctx context.Context, detectorID string) *finding.VerificationResult {
	if err := ctx.Err(); err != nil {
		return rateLimitFailure(detectorID, err)
	}

	now := time.Now()
	reservations := []*rate.Reservation{
		e.limiterFor(detectorID).ReserveN(now, 1),
		e.rateLimiter.ReserveN(now, 1),
	}
	for _, reservation := range reservations {
		if !reservation.OK() {
			cancelRateReservations(reservations, now)
			return rateLimitFailure(detectorID, fmt.Errorf("rate limiter reservation rejected"))
		}
	}

	delay := time.Duration(0)
	for _, reservation := range reservations {
		if candidate := reservation.DelayFrom(now); candidate > delay {
			delay = candidate
		}
	}
	if deadline, ok := ctx.Deadline(); ok && now.Add(delay).After(deadline) {
		cancelRateReservations(reservations, now)
		return rateLimitFailure(detectorID, context.DeadlineExceeded)
	}
	if delay <= 0 {
		if err := ctx.Err(); err != nil {
			cancelRateReservations(reservations, now)
			return rateLimitFailure(detectorID, err)
		}
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		cancelRateReservations(reservations, time.Now())
		return rateLimitFailure(detectorID, ctx.Err())
	}
}

func cancelRateReservations(reservations []*rate.Reservation, at time.Time) {
	for _, reservation := range reservations {
		if reservation != nil && reservation.OK() {
			reservation.CancelAt(at)
		}
	}
}

func rateLimitFailure(detectorID string, err error) *finding.VerificationResult {
	slog.Warn(
		"rate limiter wait cancelled",
		"detector_id", detectorID,
		"error", err,
	)
	return &finding.VerificationResult{
		Status:  finding.StatusVerifyError,
		Message: fmt.Sprintf("rate limiter cancelled: %v", err),
	}
}

func verificationRequestBudget(v RequestGatedVerifier) (int, error) {
	budget := v.VerificationRequestBudget()
	if budget < 1 {
		return 0, fmt.Errorf("verification request budget %d must be positive", budget)
	}
	if budget > maxVerificationRequestBudget {
		return 0, fmt.Errorf("verification request budget %d exceeds maximum %d", budget, maxVerificationRequestBudget)
	}
	return budget, nil
}

func safeVerificationRequestBudget(v RequestGatedVerifier) (budget int, err error) {
	defer func() {
		if recover() != nil {
			// The recovered value can contain a raw credential. Do not format,
			// return, or log it.
			budget = 0
			err = fmt.Errorf("verifier panicked while declaring its request budget")
		}
	}()
	return verificationRequestBudget(v)
}

// boundedRequestGate returns a concurrency-safe admission gate tied to one
// finding. Each successful invocation consumes one unit of the verifier's
// declared request budget and one token from both the provider and global
// limiters at the actual request send point.
func (e *Engine) boundedRequestGate(ctx context.Context, detectorID string, budget int) RequestGate {
	var mu sync.Mutex
	used := 0
	return func() *finding.VerificationResult {
		mu.Lock()
		if used >= budget {
			mu.Unlock()
			return &finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: "verifier exceeded its declared request budget",
			}
		}
		used++
		mu.Unlock()
		return e.waitRateLimit(ctx, detectorID)
	}
}

// safeVerify invokes v.Verify with panic recovery so that a single misbehaving
// verifier (for example a nil-pointer dereference while parsing an unexpected
// provider response) cannot crash the entire scan and discard already-computed
// findings. A recovered panic is converted to a StatusVerifyError result and
// logged with a stack trace; the raw secret is never logged.
func (e *Engine) safeVerify(ctx context.Context, v Verifier, raw detector.RawFinding) (result finding.VerificationResult) {
	return e.safeVerification(ctx, raw, func() finding.VerificationResult {
		return v.Verify(ctx, raw)
	})
}

func (e *Engine) safeVerifyWithRequestGate(
	ctx context.Context,
	v RequestGatedVerifier,
	raw detector.RawFinding,
	gate RequestGate,
) finding.VerificationResult {
	return e.safeVerification(ctx, raw, func() finding.VerificationResult {
		return v.VerifyWithRequestGate(ctx, raw, gate)
	})
}

func (e *Engine) safeVerification(
	ctx context.Context,
	raw detector.RawFinding,
	verify func() finding.VerificationResult,
) (result finding.VerificationResult) {
	defer func() {
		if recover() != nil {
			// Never format or log the recovered payload: a defective verifier can
			// panic with the raw credential itself. debug.Stack contains program
			// counters/function frames, not panic values or local variables.
			slog.ErrorContext(ctx,
				"verifier panicked; recovered to protect the scan",
				"detector_id", raw.DetectorID,
				"stack", string(debug.Stack()),
			)
			result = finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: "verifier panicked during verification",
			}
		}
	}()
	return verify()
}

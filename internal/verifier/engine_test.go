package verifier

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testVerifier is a configurable mock verifier for engine tests.
type testVerifier struct {
	detectorID string
	result     finding.VerificationResult
	delay      time.Duration
	callCount  atomic.Int64

	// inFlight tracks how many Verify calls are currently executing, and
	// maxInFlight records the peak. They let tests assert genuine concurrency
	// deterministically without timing real sleeps.
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
}

func (v *testVerifier) Type() string { return v.detectorID }

func (v *testVerifier) Verify(ctx context.Context, _ detector.RawFinding) finding.VerificationResult {
	v.callCount.Add(1)

	cur := v.inFlight.Add(1)
	defer v.inFlight.Add(-1)
	for {
		peak := v.maxInFlight.Load()
		if cur <= peak || v.maxInFlight.CompareAndSwap(peak, cur) {
			break
		}
	}

	if v.delay > 0 {
		select {
		case <-time.After(v.delay):
		case <-ctx.Done():
			return finding.VerificationResult{
				Status:  finding.StatusVerifyError,
				Message: ctx.Err().Error(),
			}
		}
	}
	return v.result
}

// panicVerifier is a mock verifier whose Verify always panics, used to prove the
// engine recovers instead of crashing the whole scan.
type panicVerifier struct {
	detectorID string
	callCount  atomic.Int64
}

func (v *panicVerifier) Type() string { return v.detectorID }

func (v *panicVerifier) Verify(context.Context, detector.RawFinding) finding.VerificationResult {
	v.callCount.Add(1)
	panic("boom: simulated verifier defect")
}

func makePair(detectorID, redacted string) VerifyPair {
	return VerifyPair{
		Finding: finding.Finding{
			DetectorID: detectorID,
			Redacted:   redacted,
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("secret-value"),
			Redacted:   redacted,
		},
	}
}

func TestVerifyAll_Disabled_ReturnsUnmodified(t *testing.T) {
	v := &testVerifier{
		detectorID: "aws-access-key-id",
		result: finding.VerificationResult{
			Status: finding.StatusVerifiedActive,
		},
	}

	engine := NewEngine(Config{Enabled: false}, []Verifier{v})
	pairs := []VerifyPair{makePair("aws-access-key-id", "AKIA****1234")}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 1)
	assert.Equal(t, finding.StatusUnverified, results[0].Verification.Status)
	assert.Equal(t, int64(0), v.callCount.Load(), "verifier should not be called when disabled")
}

func TestVerifyAll_MatchingVerifier_UpdatesFinding(t *testing.T) {
	v := &testVerifier{
		detectorID: "github-token",
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "token is active",
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 2,
		RateLimit:   100,
	}, []Verifier{v})

	pairs := []VerifyPair{makePair("github-token", "ghp_****abcd")}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 1)
	assert.Equal(t, finding.StatusVerifiedActive, results[0].Verification.Status)
	assert.Equal(t, "token is active", results[0].Verification.Message)
	assert.Equal(t, int64(1), v.callCount.Load())
}

func TestVerifyAll_NoMatchingVerifier_LeavesUnverified(t *testing.T) {
	v := &testVerifier{
		detectorID: "aws-access-key-id",
		result: finding.VerificationResult{
			Status: finding.StatusVerifiedActive,
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 2,
		RateLimit:   100,
	}, []Verifier{v})

	pairs := []VerifyPair{makePair("unknown-detector", "XXXX****YYYY")}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 1)
	assert.Equal(t, finding.StatusUnverified, results[0].Verification.Status)
	assert.Equal(t, int64(0), v.callCount.Load(), "verifier should not be called for non-matching detector")
}

func TestVerifyAll_Timeout_ReturnsVerifyError(t *testing.T) {
	v := &testVerifier{
		detectorID: "slow-service",
		delay:      5 * time.Second,
		result: finding.VerificationResult{
			Status: finding.StatusVerifiedActive,
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     50 * time.Millisecond,
		Concurrency: 1,
		RateLimit:   100,
	}, []Verifier{v})

	pairs := []VerifyPair{makePair("slow-service", "slow****1234")}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 1)
	assert.Equal(t, finding.StatusVerifyError, results[0].Verification.Status)
}

func TestVerifyAll_MultipleFindings_VerifiesConcurrently(t *testing.T) {
	v := &testVerifier{
		detectorID: "aws-access-key-id",
		delay:      50 * time.Millisecond,
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "key is active",
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 4,
		RateLimit:   1000,
	}, []Verifier{v})

	pairs := make([]VerifyPair, 8)
	for i := range pairs {
		pairs[i] = makePair("aws-access-key-id", "AKIA****XXXX")
	}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 8)
	for _, r := range results {
		assert.Equal(t, finding.StatusVerifiedActive, r.Verification.Status)
	}

	// Deterministic concurrency check: with 4 workers and a delay that keeps
	// each call in flight, at least two verifications must overlap. This avoids
	// the flakiness of asserting a wall-clock elapsed-time bound over real
	// sleeps under loaded CI.
	assert.Greater(t, v.maxInFlight.Load(), int64(1),
		"verifications should run concurrently, not sequentially")
	assert.Equal(t, int64(8), v.callCount.Load())
}

func TestVerifyAll_ContextCancelled_ReturnsError(t *testing.T) {
	v := &testVerifier{
		detectorID: "aws-access-key-id",
		delay:      5 * time.Second,
		result: finding.VerificationResult{
			Status: finding.StatusVerifiedActive,
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     10 * time.Second,
		Concurrency: 1,
		RateLimit:   100,
	}, []Verifier{v})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	pairs := []VerifyPair{makePair("aws-access-key-id", "AKIA****ZZZZ")}

	results := engine.VerifyAll(ctx, pairs)

	require.Len(t, results, 1)
	assert.Equal(t, finding.StatusVerifyError, results[0].Verification.Status)
}

func TestVerifyAll_EmptyPairs_ReturnsEmpty(t *testing.T) {
	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 2,
		RateLimit:   100,
	}, nil)

	results := engine.VerifyAll(context.Background(), nil)

	assert.Empty(t, results)
}

func TestVerifyAll_MixedVerifiers_RoutesCorrectly(t *testing.T) {
	awsVerifier := &testVerifier{
		detectorID: "aws-access-key-id",
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "aws active",
		},
	}
	ghVerifier := &testVerifier{
		detectorID: "github-token",
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "github inactive",
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 4,
		RateLimit:   100,
	}, []Verifier{awsVerifier, ghVerifier})

	pairs := []VerifyPair{
		makePair("aws-access-key-id", "AKIA****AAAA"),
		makePair("github-token", "ghp_****bbbb"),
		makePair("unknown-type", "xxxx****yyyy"),
	}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 3)
	assert.Equal(t, finding.StatusVerifiedActive, results[0].Verification.Status)
	assert.Equal(t, "aws active", results[0].Verification.Message)
	assert.Equal(t, finding.StatusVerifiedInactive, results[1].Verification.Status)
	assert.Equal(t, "github inactive", results[1].Verification.Message)
	assert.Equal(t, finding.StatusUnverified, results[2].Verification.Status)

	assert.Equal(t, int64(1), awsVerifier.callCount.Load())
	assert.Equal(t, int64(1), ghVerifier.callCount.Load())
}

func TestVerifyAll_PanickingVerifier_RecoversAsVerifyError(t *testing.T) {
	pv := &panicVerifier{detectorID: "panic-detector"}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 1,
		RateLimit:   100,
	}, []Verifier{pv})

	pairs := []VerifyPair{makePair("panic-detector", "PANIC****0000")}

	// The call must return normally (not crash the process) and convert the
	// panic into a StatusVerifyError.
	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 1)
	assert.Equal(t, finding.StatusVerifyError, results[0].Verification.Status)
	assert.Equal(t, int64(1), pv.callCount.Load())
}

func TestVerifyAll_PanickingVerifier_OtherFindingsStillComplete(t *testing.T) {
	pv := &panicVerifier{detectorID: "panic-detector"}
	good := &testVerifier{
		detectorID: "aws-access-key-id",
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "key is active",
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 4,
		RateLimit:   1000,
	}, []Verifier{pv, good})

	pairs := []VerifyPair{
		makePair("panic-detector", "PANIC****1111"),
		makePair("aws-access-key-id", "AKIA****2222"),
		makePair("panic-detector", "PANIC****3333"),
		makePair("aws-access-key-id", "AKIA****4444"),
	}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, 4)
	// Panicking-verifier findings become verify errors; the healthy verifier's
	// findings are unaffected and complete normally.
	assert.Equal(t, finding.StatusVerifyError, results[0].Verification.Status)
	assert.Equal(t, finding.StatusVerifiedActive, results[1].Verification.Status)
	assert.Equal(t, finding.StatusVerifyError, results[2].Verification.Status)
	assert.Equal(t, finding.StatusVerifiedActive, results[3].Verification.Status)
	assert.Equal(t, int64(2), good.callCount.Load())
}

func TestVerifyAll_RaceDetectorStress_ManyConcurrentWrites(t *testing.T) {
	v := &testVerifier{
		detectorID: "stress-detector",
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "active",
		},
	}

	engine := NewEngine(Config{
		Enabled:     true,
		Timeout:     5 * time.Second,
		Concurrency: 16,
		RateLimit:   10000,
	}, []Verifier{v})

	const pairCount = 200
	pairs := make([]VerifyPair, pairCount)
	for i := range pairs {
		pairs[i] = makePair("stress-detector", "XXXX****YYYY")
	}

	results := engine.VerifyAll(context.Background(), pairs)

	require.Len(t, results, pairCount)
	for i, r := range results {
		assert.Equal(t, finding.StatusVerifiedActive, r.Verification.Status,
			"unexpected status at index %d", i)
	}
	assert.Equal(t, int64(pairCount), v.callCount.Load())
}

func TestNewEngine_DefaultValues_AppliedForZeroConfig(t *testing.T) {
	engine := NewEngine(Config{Enabled: true}, nil)

	assert.Equal(t, DefaultConcurrency, engine.concurrency)
	assert.Equal(t, DefaultTimeout, engine.timeout)
	assert.True(t, engine.enabled)
}

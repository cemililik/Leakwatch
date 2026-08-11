package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/custom"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// fakeSource is an in-memory source.Source that yields a single chunk. It lets
// the scanner pipeline be driven end-to-end without touching disk or network.
type fakeSource struct {
	data []byte
}

func (f *fakeSource) Type() string                   { return "fake" }
func (f *fakeSource) Validate(context.Context) error { return nil }
func (f *fakeSource) Err() error                     { return nil }

func (f *fakeSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk)
	go func() {
		defer close(ch)
		select {
		case ch <- source.Chunk{
			Data:           f.data,
			SourceMetadata: finding.SourceMetadata{SourceType: "fake", FilePath: "mem.txt"},
		}:
		case <-ctx.Done():
		}
	}()
	return ch
}

func hasDetectorID(detectors []detector.Detector, id string) bool {
	for _, d := range detectors {
		if d.ID() == id {
			return true
		}
	}
	return false
}

func TestBuildEngineConfig_CustomRules_NoGlobalRegistryMutation(t *testing.T) {
	before := len(detector.All())

	cfg := &Config{
		Concurrency: 1,
		CustomRules: []custom.RuleDef{{
			ID:       "unit-custom-rule",
			Regex:    `X_[a-z]{8}`,
			Keywords: []string{"X_"},
			Severity: "medium",
		}},
	}

	engCfg, err := BuildEngineConfig(cfg)
	require.NoError(t, err)
	assert.True(t, hasDetectorID(engCfg.Detectors, "unit-custom-rule"),
		"custom rule must be threaded into the engine's detector slice")

	// The process-global registry must NOT have grown: custom rules are threaded
	// through engine.Config, not registered globally.
	assert.Equal(t, before, len(detector.All()),
		"custom rule registration must not mutate the global detector registry")

	// Idempotent: a second identical build still includes the custom rule.
	// (Previously the second call rejected it via RegisterIfAbsent's false return.)
	engCfg2, err := BuildEngineConfig(cfg)
	require.NoError(t, err)
	assert.True(t, hasDetectorID(engCfg2.Detectors, "unit-custom-rule"),
		"BuildEngineConfig must be idempotent across repeated calls")
	assert.Equal(t, before, len(detector.All()))
}

func TestBuildEngineConfig_ExcludeDetectors_RemovesByID(t *testing.T) {
	cfg := &Config{
		Concurrency: 1,
		CustomRules: []custom.RuleDef{
			{ID: "keep-rule", Regex: `K_[a-z]{6}`, Keywords: []string{"K_"}, Severity: "low"},
			{ID: "drop-rule", Regex: `D_[a-z]{6}`, Keywords: []string{"D_"}, Severity: "low"},
		},
		ExcludeDetectors: []string{"drop-rule"},
	}

	engCfg, err := BuildEngineConfig(cfg)
	require.NoError(t, err)
	assert.True(t, hasDetectorID(engCfg.Detectors, "keep-rule"))
	assert.False(t, hasDetectorID(engCfg.Detectors, "drop-rule"))
}

func TestBuildEngineConfig_NoVerifyOverridesEnabled(t *testing.T) {
	cfg := &Config{
		Concurrency:   1,
		CustomRules:   []custom.RuleDef{{ID: "r", Regex: `R_[a-z]{4}`, Keywords: []string{"R_"}, Severity: "low"}},
		VerifyEnabled: true,
		NoVerify:      true,
	}
	engCfg, err := BuildEngineConfig(cfg)
	require.NoError(t, err)
	assert.False(t, engCfg.VerifierConfig.Enabled, "--no-verify must override verification.enabled")
}

func TestRun_CustomRule_DetectsSyntheticSecret(t *testing.T) {
	cfg := &Config{
		Concurrency: 2,
		CustomRules: []custom.RuleDef{{
			ID:          "synthetic-token",
			Description: "test-only synthetic token",
			Regex:       `SYN_[A-Z0-9]{16}`,
			Keywords:    []string{"SYN_"},
			Severity:    "high",
		}},
		VerifyEnabled: false,
	}
	// Synthetic (fake) secret — never a real credential.
	src := &fakeSource{data: []byte("api_key = SYN_ABCDEF0123456789\n")}

	result, err := Run(context.Background(), cfg, src)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "synthetic-token", result.Findings[0].DetectorID)
	assert.Equal(t, finding.SeverityHigh, result.Findings[0].Severity)
	assert.False(t, result.Interrupted)
}

func TestRun_CancelledContext_ReturnsInterruptedResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the scan starts

	cfg := &Config{
		Concurrency:   1,
		CustomRules:   []custom.RuleDef{{ID: "z", Regex: `Z_[a-z]{4}`, Keywords: []string{"Z_"}, Severity: "low"}},
		VerifyEnabled: false,
	}
	src := &fakeSource{data: []byte("Z_abcd")}

	result, err := Run(ctx, cfg, src)
	require.NotNil(t, result, "an interrupted scan must still return a (partial) result")
	assert.True(t, result.Interrupted)
	require.Error(t, err)
}

// TestScanReposParallel_SharesSingleEngine proves the multi-repo orchestration
// reuses ONE engine — and therefore one shared verifier rate limiter — across
// every repository, instead of constructing a fresh limiter per repo (which would
// multiply the effective API request rate by the parallelism factor).
func TestScanReposParallel_SharesSingleEngine(t *testing.T) {
	eng := engine.New(engine.Config{Concurrency: 1})

	var mu sync.Mutex
	seen := map[*engine.Engine]int{}
	scanOne := func(_ context.Context, e *engine.Engine, _ string) (*engine.ScanResult, error) {
		mu.Lock()
		seen[e]++
		mu.Unlock()
		return &engine.ScanResult{Findings: []finding.Finding{}, ScannedChunks: 1}, nil
	}

	urls := []string{"r1", "r2", "r3", "r4", "r5"}
	findings, chunks, errs := scanReposParallel(context.Background(), eng, urls, 3, scanOne)

	assert.Empty(t, errs)
	assert.Empty(t, findings)
	assert.Equal(t, len(urls), chunks)
	require.Len(t, seen, 1, "exactly one engine pointer must be shared across all repos")
	assert.Equal(t, len(urls), seen[eng])
}

func TestScanReposParallel_AggregatesFindingsAndErrors(t *testing.T) {
	eng := engine.New(engine.Config{Concurrency: 1})
	partialErr := fmt.Errorf("partial")

	scanOne := func(_ context.Context, _ *engine.Engine, url string) (*engine.ScanResult, error) {
		switch url {
		case "fail":
			// Fatal failure before any result: recorded as an error.
			return nil, fmt.Errorf("clone failed")
		case "partial":
			// Partial result WITH an error (e.g. interrupted mid-scan): findings
			// and its error must both be aggregated.
			return &engine.ScanResult{Findings: []finding.Finding{{ID: "p"}}, ScannedChunks: 1}, partialErr
		default:
			return &engine.ScanResult{Findings: []finding.Finding{{ID: url}}, ScannedChunks: 2}, nil
		}
	}

	urls := []string{"ok1", "ok2", "fail", "partial"}
	findings, chunks, errs := scanReposParallel(context.Background(), eng, urls, 2, scanOne)

	assert.Len(t, errs, 2, "both fatal and partial-result failures must be recorded")
	assert.ErrorIs(t, errors.Join(errs...), partialErr)
	assert.Len(t, findings, 3, "ok1, ok2 and partial's findings are aggregated")
	assert.Equal(t, 2+2+1, chunks)
}

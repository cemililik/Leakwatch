// Package scanner holds the Leakwatch scan orchestration that used to live in the
// cmd/ layer: assembling the engine configuration, running a single-source scan,
// running multiple git repositories in parallel, and post-processing results
// (.leakwatchignore filtering and remediation enrichment).
//
// Keeping this logic out of cmd/ restores the "thin wiring layer" contract that
// package cmd declares for itself (ADR-0002) and makes the pipeline — including
// the concurrent multi-repo orchestration — unit- and race-testable without any
// Cobra plumbing.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/custom"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/remediation"
	"github.com/HodeTech/leakwatch/internal/source"
	gitsource "github.com/HodeTech/leakwatch/internal/source/git"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Config holds the fully-resolved settings for a scan, independent of Cobra and
// Viper. The cmd/ layer parses flags/config into this struct and hands it to the
// scanner entry points; nothing here references a *cobra.Command or *pflag.Flag.
type Config struct {
	Concurrency      int
	MaxFileSize      int64    // used by cmd/ to build sources
	ExcludePaths     []string // used by cmd/ to build sources
	ExcludeDetectors []string
	EnableEntropy    bool
	EntropyThreshold float64
	ShowRaw          bool
	OutputFile       string
	Format           string

	NoVerify          bool
	OnlyVerified      bool
	MinSeverity       finding.Severity
	EnableRemediation bool

	// ScanRoot is the root path used to discover a .leakwatchignore file (in
	// addition to the current working directory). It is empty for sources with no
	// meaningful local root (remote repos, buckets, images, Slack).
	ScanRoot string
	// ScanTarget is a display name for the scan summary (path, URL, image ref).
	ScanTarget string

	// Verification engine settings sourced from the `verification:` config block.
	VerifyEnabled     bool
	VerifyTimeout     time.Duration
	VerifyConcurrency int
	VerifyRateLimit   float64
	// GrafanaInstanceURL is accepted only from the explicit command-line flag,
	// never from repository config or detector ExtraData. It is therefore a
	// trusted operator choice rather than scan-controlled input.
	GrafanaInstanceURL string
	// TrustedVerifierOrigins maps a context-required detector ID to an HTTPS
	// origin explicitly supplied by the operator on this invocation. The cmd
	// layer never resolves this map from project configuration or environment
	// variables, preventing scanned repositories from choosing credential
	// destinations.
	TrustedVerifierOrigins map[string]string

	// CustomRules are user-defined YAML custom rules from the `custom-rules:`
	// config block. BuildEngineConfig compiles them into detectors threaded
	// through engine.Config without touching the process-global detector
	// registry, so repeated scans in one process stay idempotent.
	CustomRules []custom.RuleDef
}

// BuildEngineConfig assembles the engine.Config shared by every scan command.
//
// Custom rules are compiled into detectors and appended to a local slice built
// from detector.All(); the process-global registry is never mutated, which makes
// BuildEngineConfig idempotent and test-isolated (previously each scan wrote its
// custom rules into the global registry, so a second call in the same process
// silently rejected them). A custom rule whose ID collides with an existing
// detector is skipped with a warning, matching the previous non-panicking
// registration semantics.
func BuildEngineConfig(cfg *Config) (engine.Config, error) {
	detectors := detector.All()

	if len(cfg.CustomRules) > 0 {
		existing := make(map[string]bool, len(detectors))
		for _, d := range detectors {
			existing[d.ID()] = true
		}
		added := 0
		for _, def := range cfg.CustomRules {
			det, err := custom.NewFromDef(def)
			if err != nil {
				slog.Warn("custom rule skipped", "error", err)
				continue
			}
			if existing[det.ID()] {
				slog.Warn("custom rule skipped: ID already in use", "id", det.ID())
				continue
			}
			existing[det.ID()] = true
			detectors = append(detectors, det)
			added++
		}
		slog.Info("custom rules loaded", "count", added, "requested", len(cfg.CustomRules))
	}

	if len(cfg.ExcludeDetectors) > 0 {
		detectors = excludeDetectorsByID(detectors, cfg.ExcludeDetectors)
	}
	if len(detectors) == 0 {
		return engine.Config{}, fmt.Errorf("no registered detectors found")
	}
	slog.Debug("detectors loaded", "count", len(detectors))

	// Configure verification from the `verification:` config block. The
	// --no-verify CLI flag takes precedence over the config value.
	verifierCfg := verifier.Config{
		Enabled:     cfg.VerifyEnabled,
		Timeout:     cfg.VerifyTimeout,
		Concurrency: cfg.VerifyConcurrency,
		RateLimit:   cfg.VerifyRateLimit,
	}
	if cfg.NoVerify {
		verifierCfg.Enabled = false
	}
	if cfg.OnlyVerified && cfg.NoVerify {
		slog.Warn("--only-verified has no effect when --no-verify is set")
	}

	verifiers, err := configuredVerifiers(cfg)
	if err != nil {
		return engine.Config{}, err
	}

	return engine.Config{
		Concurrency:      cfg.Concurrency,
		Detectors:        detectors,
		EnableEntropy:    cfg.EnableEntropy,
		EntropyThreshold: cfg.EntropyThreshold,
		ShowRaw:          cfg.ShowRaw,
		VerifierConfig:   verifierCfg,
		Verifiers:        verifiers,
		OnlyVerified:     cfg.OnlyVerified,
		MinSeverity:      cfg.MinSeverity,
	}, nil
}

func configuredVerifiers(cfg *Config) ([]verifier.Verifier, error) {
	verifiers := verifier.All()
	origins := make(map[string]string, len(cfg.TrustedVerifierOrigins)+1)
	for detectorID, origin := range cfg.TrustedVerifierOrigins {
		origins[detectorID] = origin
	}
	if cfg.GrafanaInstanceURL != "" {
		if origin, exists := origins["grafana-api-key"]; exists && origin != cfg.GrafanaInstanceURL {
			return nil, fmt.Errorf("configure trusted verification: conflicting Grafana origins were supplied")
		}
		origins["grafana-api-key"] = cfg.GrafanaInstanceURL
	}
	if len(origins) == 0 {
		return verifiers, nil
	}

	ids := make([]string, 0, len(origins))
	for detectorID := range origins {
		ids = append(ids, detectorID)
	}
	sort.Strings(ids)

	configured := verifiers
	for _, detectorID := range ids {
		var err error
		configured, err = verifier.ConfigureTrustedInstance(configured, detectorID, origins[detectorID])
		if err != nil {
			return nil, fmt.Errorf("configure trusted verification for %q: %w", detectorID, err)
		}
	}
	return configured, nil
}

// Run executes a single-source scan: it builds the engine, runs the scan under
// the given (already signal-aware) context, and post-processes the result
// (.leakwatchignore filtering and remediation enrichment).
//
// It returns the engine's scan result together with the scan error. The error is
// non-nil on interruption (ctx cancelled) or a terminal source failure; in the
// interruption case a partial, non-nil result is still returned so the caller can
// render partial findings and choose a distinct interrupted exit code. Only a
// a non-cancellation pre-scan failure yields a nil result. Cancellation during
// source validation returns an interrupted, non-nil result so the CLI can map
// it to exit code 3 instead of a generic failure.
func Run(ctx context.Context, cfg *Config, src source.Source) (*engine.ScanResult, error) {
	engCfg, err := BuildEngineConfig(cfg)
	if err != nil {
		return nil, err
	}

	eng := engine.New(engCfg)
	result, scanErr := eng.Scan(ctx, src)
	if result == nil {
		return nil, scanErr
	}

	postProcess(cfg, result, cfg.ScanRoot)
	return result, scanErr
}

// ScanRepos scans multiple git repositories in parallel and combines their
// findings into a single result.
//
// A SINGLE engine (and therefore a single shared verifier rate limiter) is
// constructed once and reused across every repository goroutine, so the
// configured verification.rate-limit is enforced globally rather than being
// multiplied by the parallelism factor. Repositories are cloned/scanned
// concurrently up to `parallel` at a time; findings are aggregated under a mutex
// and post-processed identically to a single-source scan (the ignore root is
// empty because repos are remote/temporary clones — only a CWD .leakwatchignore
// applies).
//
// The returned error is non-nil when one or more repositories failed to scan
// (distinct from findings, which are surfaced via the result). The combined
// result's Interrupted flag reflects context cancellation.
func ScanRepos(ctx context.Context, cfg *Config, repoURLs []string, srcOpts []gitsource.Option, parallel int) (*engine.ScanResult, error) {
	if parallel < 1 {
		parallel = 1
	}

	engCfg, err := BuildEngineConfig(cfg)
	if err != nil {
		return nil, err
	}
	// One shared engine across all repos -> one shared verifier rate limiter.
	eng := engine.New(engCfg)

	scanStart := time.Now()

	scanOne := func(ctx context.Context, eng *engine.Engine, url string) (*engine.ScanResult, error) {
		// displayURL strips any embedded credentials so a URL like
		// https://user:TOKEN@host/repo.git never leaks to logs, errors, or output.
		// The raw url is still passed to gitsource.New for cloning.
		displayURL := gitsource.SafeDisplayURL(url)
		slog.Info("scanning repository", "url", displayURL)

		src := gitsource.New(url, srcOpts...)
		result, scanErr := eng.Scan(ctx, src)
		if closeErr := src.Close(); closeErr != nil {
			slog.Warn("failed to clean up repo", "url", displayURL, "error", closeErr)
		}
		if result != nil {
			slog.Info("repository scan completed", "url", displayURL, "findings", len(result.Findings), "files", result.ScannedChunks)
		}
		if scanErr != nil {
			return result, fmt.Errorf("scan failed for %s: %w", displayURL, scanErr)
		}
		return result, nil
	}

	findings, chunks, scanErrors := scanReposParallel(ctx, eng, repoURLs, parallel, scanOne)

	for _, e := range scanErrors {
		slog.Error("scan error", "error", e)
	}

	combined := &engine.ScanResult{
		Findings:      findings,
		ScannedChunks: chunks,
		Duration:      time.Since(scanStart),
		Interrupted:   ctx.Err() != nil,
	}
	postProcess(cfg, combined, "")

	var aggErr error
	if len(scanErrors) > 0 {
		aggErr = fmt.Errorf("%d repository scans failed", len(scanErrors))
	}
	return combined, aggErr
}

// scanReposParallel runs scanOne for each repo URL with bounded parallelism,
// reusing the single shared engine, and aggregates findings/chunks/errors under a
// mutex.
//
// A repo that returns a nil result contributes only its error (a fatal
// pre-findings failure); a repo that returns a non-nil result contributes its
// findings even if it also returned an error (a partial result from an
// interrupted or partially-failed scan), matching the engine's partial-result
// contract. scanOne is injected so the concurrent orchestration can be
// race-tested with an in-memory scan function instead of a real git clone.
func scanReposParallel(
	ctx context.Context,
	eng *engine.Engine,
	repoURLs []string,
	parallel int,
	scanOne func(ctx context.Context, eng *engine.Engine, url string) (*engine.ScanResult, error),
) (findings []finding.Finding, chunks int, errs []error) {
	sem := make(chan struct{}, parallel)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, repoURL := range repoURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			result, err := scanOne(ctx, eng, url)

			mu.Lock()
			defer mu.Unlock()
			if result == nil {
				if err != nil {
					errs = append(errs, err)
				}
				return
			}
			findings = append(findings, result.Findings...)
			chunks += result.ScannedChunks
		}(repoURL)
	}

	wg.Wait()
	return findings, chunks, errs
}

// postProcess applies the shared post-scan steps to an already-produced result:
// .leakwatchignore filtering (searched in ignoreRoot, then CWD) and, when
// enabled, remediation enrichment. It normalizes a nil findings slice to an empty
// one so downstream formatters always see a non-nil slice.
func postProcess(cfg *Config, result *engine.ScanResult, ignoreRoot string) {
	result.Findings = applyLeakwatchIgnore(result.Findings, ignoreRoot)
	if cfg.EnableRemediation {
		result.Findings = remediation.EnrichFindings(result.Findings)
	}
	if result.Findings == nil {
		result.Findings = []finding.Finding{}
	}
}

// applyLeakwatchIgnore filters findings through the first .leakwatchignore found
// in scanRoot, then the current working directory. scanRoot may be empty.
func applyLeakwatchIgnore(findings []finding.Finding, scanRoot string) []finding.Finding {
	var ignoreRules *filter.IgnoreRules
	for _, dir := range []string{scanRoot, "."} {
		if dir == "" {
			continue
		}
		ignorePath := filepath.Join(dir, ".leakwatchignore")
		if rules, err := filter.LoadIgnoreFile(ignorePath); err == nil {
			ignoreRules = rules
			slog.Debug("loaded .leakwatchignore", "path", ignorePath)
			break
		}
	}
	if ignoreRules == nil {
		return findings
	}
	filtered := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if !ignoreRules.ShouldIgnore(f.SourceMetadata.FilePath) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// excludeDetectorsByID returns the detectors whose ID is not in the exclude list.
func excludeDetectorsByID(detectors []detector.Detector, exclude []string) []detector.Detector {
	excluded := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}
	kept := make([]detector.Detector, 0, len(detectors))
	for _, d := range detectors {
		if excluded[d.ID()] {
			slog.Debug("detector excluded by config", "detector_id", d.ID())
			continue
		}
		kept = append(kept, d)
	}
	return kept
}

// Package engine provides the Leakwatch scan engine.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/entropy"
	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/matcher"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	// defaultEntropyThreshold is the default Shannon entropy threshold.
	defaultEntropyThreshold = 4.0

	// channelBufferMultiplier is the channel buffer size multiplier.
	channelBufferMultiplier = 2

	// hashTruncateLen is the Finding ID hash truncation length in bytes.
	// 16 bytes = 128 bits provides sufficient collision resistance.
	hashTruncateLen = 16

	// maxPairsInFlight bounds how many detected VerifyPairs (each carrying raw
	// secret bytes) are held in memory before they are streamed into
	// verification and released. It caps peak memory for secret-dense inputs so
	// it no longer grows with the total number of findings (see ENG-M-02).
	maxPairsInFlight = 1024
)

// Config holds the scan engine configuration.
type Config struct {
	Concurrency   int
	Detectors     []detector.Detector
	EnableEntropy bool
	// EntropyThreshold is the minimum Shannon entropy a HEURISTIC match must have
	// to be reported. When EnableEntropy is set the engine computes
	// Finding.Entropy for every match (informational), but only drops a finding
	// when its detector opts into the gate via EntropyBased() — i.e. the generic
	// API-key detector and other high-entropy-string heuristics. A mixed detector
	// may refine that decision per finding via EntropyGated(raw), preserving the
	// gate for heuristic matches while exempting strong structural context.
	// Structural detectors (AWS, GitHub, Stripe, …) are never entropy-gated, so a
	// valid but low-entropy key is always reported. When EnableEntropy is false no
	// entropy is computed and no gating is applied. Defaulted to
	// defaultEntropyThreshold.
	EntropyThreshold float64
	ShowRaw          bool
	Clock            func() time.Time // Optional; defaults to time.Now
	VerifierConfig   verifier.Config
	Verifiers        []verifier.Verifier
	OnlyVerified     bool             // If true, only return verified active findings
	MinSeverity      finding.Severity // Minimum severity to include in results
}

// ScanResult represents the outcome of a scan.
type ScanResult struct {
	Findings      []finding.Finding
	ScannedChunks int
	Duration      time.Duration
	Interrupted   bool
}

// Engine is the scan engine that orchestrates detection and verification.
type Engine struct {
	config   Config
	matcher  *matcher.Matcher
	verifyEn *verifier.Engine
}

// New creates a new scan engine.
// The Aho-Corasick automaton is compiled from detector keywords.
func New(cfg Config) *Engine {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	// EntropyThreshold is defaulted here so that enabling entropy analysis
	// without an explicit threshold still gates on a sensible value. The gate is
	// applied in worker only when EnableEntropy is set.
	if cfg.EntropyThreshold <= 0 {
		cfg.EntropyThreshold = defaultEntropyThreshold
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Engine{
		config:   cfg,
		matcher:  matcher.New(cfg.Detectors),
		verifyEn: verifier.NewEngine(cfg.VerifierConfig, cfg.Verifiers),
	}
}

// entropyBased is an optional interface a detector implements when its matches
// are heuristic (high-entropy-string) rather than structurally precise. Only
// such detectors are subject to the engine's Shannon-entropy floor; every other
// detector reports its matches regardless of entropy.
type entropyBased interface {
	EntropyBased() bool
}

// findingEntropyGate is an optional refinement for mixed detectors that emit
// both heuristic and structurally contextual findings. It lets the detector
// retain the global entropy gate for heuristic matches while exempting only a
// specific raw finding backed by strong structure.
type findingEntropyGate interface {
	EntropyGated(raw detector.RawFinding) bool
}

// isEntropyBased reports whether the detector opts into the engine entropy gate.
func isEntropyBased(d detector.Detector) bool {
	eb, ok := d.(entropyBased)
	return ok && eb.EntropyBased()
}

func isEntropyGated(d detector.Detector, raw detector.RawFinding) bool {
	if policy, ok := d.(findingEntropyGate); ok {
		return policy.EntropyGated(raw)
	}
	return isEntropyBased(d)
}

// Scan scans the given source and returns results.
func (e *Engine) Scan(ctx context.Context, src source.Source) (*ScanResult, error) {
	if err := src.Validate(); err != nil {
		return nil, fmt.Errorf("source validation failed: %w", err)
	}

	start := time.Now()

	slog.Info(
		"scan started",
		"source", src.Type(),
		"concurrency", e.config.Concurrency,
		"detectors", len(e.config.Detectors),
	)

	jobs := make(chan source.Chunk, e.config.Concurrency*channelBufferMultiplier)
	results := make(chan verifier.VerifyPair, e.config.Concurrency*channelBufferMultiplier)

	// Start workers.
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.worker(ctx, jobs, results)
		}()
	}

	// Collect and verify results incrementally (bounded streaming).
	//
	// Raw secret byte lifetime: each VerifyPair carries the raw secret bytes
	// (p.Raw) in memory only so that verification can re-present them to the
	// relevant API. These bytes are never logged, written to disk, or otherwise
	// persisted (per the project's secret-safety rule).
	//
	// Memory bound (ENG-M-02, resolved): rather than accumulating every detected
	// pair for the whole scan before verifying, the collector buffers at most
	// maxPairsInFlight pairs, streams that batch into verification, appends the
	// resulting findings, and drops its references to the raw bytes so they
	// become garbage-collectable immediately. Peak raw-secret memory is therefore
	// bounded by maxPairsInFlight rather than by the total number of findings.
	var findings []finding.Finding
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		batch := make([]verifier.VerifyPair, 0, maxPairsInFlight)
		flush := func() {
			if len(batch) == 0 {
				return
			}
			findings = append(findings, e.verifyBatch(ctx, batch)...)
			// Drop references to raw secret bytes so they are GC-eligible now
			// instead of living until the whole scan completes.
			for i := range batch {
				batch[i] = verifier.VerifyPair{}
			}
			batch = batch[:0]
		}
		for p := range results {
			batch = append(batch, p)
			if len(batch) >= maxPairsInFlight {
				flush()
			}
		}
		flush()
	}()

	// Send chunks to the jobs channel.
	// NOTE: Context cancellation during this loop depends on the source implementation
	// closing its Chunks channel promptly when ctx is cancelled. If a source blocks
	// indefinitely on send, this loop may not exit until the source returns.
	scannedChunks := 0
	// fullyDrained is true only when the range below exits because the source
	// closed its chunks channel (normal completion), false when we break out
	// early on cancellation. It gates the src.Err() read below: reading the
	// source's terminal error is only race-free once its channel is closed.
	fullyDrained := true
loop:
	for chunk := range src.Chunks(ctx) {
		select {
		case <-ctx.Done():
			fullyDrained = false
			break loop
		case jobs <- chunk:
			scannedChunks++
		}
	}
	close(jobs)

	// Surface the source's terminal outcome. src.Err() is only valid to read
	// after the source's chunks channel is fully drained (closed); that close is
	// the happens-before edge publishing the error the source recorded before
	// closing. On the cancellation break path the source goroutine may still be
	// running, so we skip the read and let the interrupt path below report the
	// outcome instead.
	var srcErr error
	if fullyDrained {
		srcErr = src.Err()
		if srcErr == nil && scannedChunks == 0 {
			// A clean scan that produced nothing: make the silently-empty result
			// visible so "0 findings, nothing scanned" is not mistaken for a
			// verified-clean target.
			slog.Warn("scan target yielded no scannable content", "source", src.Type())
		}
	}

	// Wait for workers to finish
	wg.Wait()
	close(results)

	// Wait for the collector (which also ran verification) to finish.
	collectWg.Wait()

	// Apply post-scan filters.
	findings = e.applyFilters(findings)

	// Impose a single deterministic order so output is stable run-to-run.
	sortFindings(findings)

	result := &ScanResult{
		Findings:      findings,
		ScannedChunks: scannedChunks,
		Duration:      time.Since(start),
		Interrupted:   ctx.Err() != nil,
	}

	slog.Info(
		"scan completed",
		"findings", len(findings),
		"chunks", scannedChunks,
		"duration", result.Duration,
		"interrupted", result.Interrupted,
	)

	if ctx.Err() != nil {
		return result, fmt.Errorf("scan interrupted: %w", ctx.Err())
	}

	// A terminal source failure must not be reported as a clean, empty scan: the
	// engine surfaces it as an error even though a (possibly partial) result is
	// still returned alongside it.
	if srcErr != nil {
		return result, fmt.Errorf("scan source failed: %w", srcErr)
	}

	return result, nil
}

// verifyBatch verifies a bounded batch of collected pairs and returns the
// resulting findings.
//
// Deduplication: identical secrets (same detector ID + raw value) are verified
// exactly once per batch and the verification result is shared across every
// finding that carries them. The findings themselves are never collapsed — each
// keeps its own distinct Finding.ID and location — so same-line/same-value
// repeats still appear as separate output entries without triggering duplicate
// verifier calls.
//
// Cancellation: when ctx is already cancelled the verifier worker pool is not
// spun up at all; pairs are passed through as-is (StatusUnverified) rather than
// being mislabeled StatusVerifyError by a rate limiter that fails immediately.
func (e *Engine) verifyBatch(ctx context.Context, batch []verifier.VerifyPair) []finding.Finding {
	if len(batch) == 0 {
		return nil
	}

	if ctx.Err() != nil {
		out := make([]finding.Finding, len(batch))
		for i, p := range batch {
			out[i] = p.Finding
		}
		return out
	}

	// Deduplicate by (detector ID + raw value). The raw value is used only as an
	// in-memory map key here; it is never logged or persisted.
	uniqueIdx := make(map[string]int, len(batch))
	uniquePairs := make([]verifier.VerifyPair, 0, len(batch))
	mapping := make([]int, len(batch))
	for i, p := range batch {
		key := p.Raw.DetectorID + "\x00" + string(p.Raw.Raw)
		idx, ok := uniqueIdx[key]
		if !ok {
			idx = len(uniquePairs)
			uniqueIdx[key] = idx
			uniquePairs = append(uniquePairs, p)
		}
		mapping[i] = idx
	}

	verifiedUnique := e.verifyEn.VerifyAll(ctx, uniquePairs)

	out := make([]finding.Finding, len(batch))
	for i, p := range batch {
		f := p.Finding
		f.Verification = verifiedUnique[mapping[i]].Verification
		out[i] = f
	}
	return out
}

// worker reads chunks from the jobs channel, runs matched detectors, and sends
// VerifyPair results. It exits cleanly when the channel is closed or context is cancelled.
func (e *Engine) worker(ctx context.Context, jobs <-chan source.Chunk, results chan<- verifier.VerifyPair) {
	for chunk := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Aho-Corasick pre-filtering: only run matched detectors.
		matchedDetectors := e.matcher.Match(chunk.Data)

		for _, det := range matchedDetectors {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// det.Scan runs inline. Cancellation latency is bounded by a single
			// detector scan: the ctx check above runs before each detector, and
			// Go's regexp engine (RE2) is linear-time with no catastrophic
			// backtracking, so a scan always terminates. Wrapping each scan in a
			// goroutine to abandon it mid-flight would add a goroutine and a
			// channel per detector per chunk for no correctness gain.
			rawFindings := det.Scan(ctx, chunk.Data)

			// Track the search position per raw value so repeated matches of the
			// same bytes resolve to distinct offsets. Detectors emit findings in
			// left-to-right match order (regexp.FindAll guarantees this; this
			// engine-level assumption is documented here because the Detector
			// interface does not encode it), so the Nth occurrence of a raw value
			// maps to its Nth position in the chunk. The cursor map is allocated
			// only when a detector returns more than one finding — the common
			// zero/one-finding case uses a plain index scan.
			var offsetCursor map[string]int
			if len(rawFindings) > 1 {
				offsetCursor = make(map[string]int, len(rawFindings))
			}

			for _, raw := range rawFindings {
				var offset int
				if offsetCursor != nil {
					offset = nextMatchOffset(chunk.Data, raw.Raw, offsetCursor)
				} else {
					offset = firstMatchOffset(chunk.Data, raw.Raw)
				}

				// Resolve the 1-based line number and its text in a single pass;
				// both the ID/line derivation and the inline-ignore check reuse it
				// instead of scanning the chunk prefix twice.
				lineNum, lineText := resolveLine(chunk.Data, chunk.SourceMetadata.Line, offset)

				f := e.rawToFinding(raw, chunk, det, lineNum, offset)

				// Entropy gating: the Shannon-entropy floor applies ONLY to
				// heuristic detectors that opt in via EntropyBased() (e.g. the
				// generic API-key detector), subject to an optional per-finding
				// EntropyGated refinement for mixed structural/heuristic detectors.
				// Structural findings — AWS, GitHub, Stripe, explicit provider
				// header contexts, etc. — are never dropped on entropy.
				if e.config.EnableEntropy && len(raw.Raw) > 0 &&
					isEntropyGated(det, raw) && f.Entropy < e.config.EntropyThreshold {
					continue
				}

				// Honor inline ignore markers (# leakwatch:ignore[:<id>]) on the
				// finding's source line. Skipped before verification so ignored
				// secrets never trigger a network call.
				if lineNum > 0 && filter.HasInlineIgnoreForDetector(lineText, det.ID()) {
					continue
				}

				pair := verifier.VerifyPair{Finding: f, Raw: raw}
				select {
				case <-ctx.Done():
					return
				case results <- pair:
				}
			}
		}
	}
}

// firstMatchOffset returns the byte offset of the first occurrence of raw in
// data, or -1 when raw is empty or absent. Used on the common path where a
// detector returns at most one finding, avoiding the per-value cursor map.
func firstMatchOffset(data, raw []byte) int {
	if len(raw) == 0 {
		return -1
	}
	return bytes.Index(data, raw)
}

// nextMatchOffset returns the byte offset of the next occurrence of raw in
// data, starting from the cursor position recorded for that raw value, and
// advances the cursor past it. This makes repeated matches of the same bytes
// resolve to distinct offsets (and therefore distinct line numbers) instead of
// all collapsing onto the first occurrence. Returns -1 when raw is empty or no
// further occurrence exists.
func nextMatchOffset(data, raw []byte, cursor map[string]int) int {
	if len(raw) == 0 {
		return -1
	}
	key := string(raw)
	from := cursor[key]
	if from > len(data) {
		return -1
	}
	idx := bytes.Index(data[from:], raw)
	if idx < 0 {
		return -1
	}
	abs := from + idx
	cursor[key] = abs + 1 // next search starts just past this match
	return abs
}

// resolveLine returns the 1-based line number and CR-trimmed text of the line a
// match belongs to, computed in a single pass over data.
//   - When the source already supplied a line (providedLine != 0) it is trusted
//     and the corresponding line text is extracted for the inline-ignore check.
//   - Otherwise the line is derived from the match's byte offset.
//   - When neither is available it returns (0, "").
func resolveLine(data []byte, providedLine, offset int) (int, string) {
	if providedLine != 0 {
		return providedLine, getLineText(data, providedLine)
	}
	if offset >= 0 {
		return lineInfoAt(data, offset)
	}
	return 0, ""
}

// lineInfoAt returns the 1-based line number containing the byte at offset and
// that line's CR-trimmed text, in a single pass.
func lineInfoAt(data []byte, offset int) (int, string) {
	if offset < 0 {
		return 0, ""
	}
	if offset > len(data) {
		offset = len(data)
	}
	lineStart := 0
	newlines := 0
	for i := 0; i < offset; i++ {
		if data[i] == '\n' {
			newlines++
			lineStart = i + 1
		}
	}
	lineEnd := lineStart
	for lineEnd < len(data) && data[lineEnd] != '\n' {
		lineEnd++
	}
	return newlines + 1, string(trimTrailingCR(data[lineStart:lineEnd]))
}

// getLineText returns the CR-trimmed text of the 1-based lineNum in data, or ""
// when lineNum is out of range. Used when the source supplied a line number but
// no byte offset is available.
func getLineText(data []byte, lineNum int) string {
	if lineNum < 1 {
		return ""
	}
	current := 1
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] != '\n' {
			continue
		}
		if current == lineNum {
			return string(trimTrailingCR(data[start:i]))
		}
		current++
		start = i + 1
	}
	if current == lineNum {
		return string(trimTrailingCR(data[start:]))
	}
	return ""
}

// trimTrailingCR removes a single trailing carriage return so CRLF files behave
// like LF files.
func trimTrailingCR(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\r' {
		return b[:len(b)-1]
	}
	return b
}

// rawToFinding converts a raw detector finding to an enriched Finding.
// Generates a deterministic ID and optionally calculates entropy.
// lineNum is the resolved 1-based source line (0 when unknown); offset is the
// byte position of this match within chunk.Data (-1 if unknown) and is folded
// into the ID so two identical matches on the same line still receive distinct
// Finding.IDs.
func (e *Engine) rawToFinding(raw detector.RawFinding, chunk source.Chunk, det detector.Detector, lineNum, offset int) finding.Finding {
	f := finding.Finding{
		DetectorID:     det.ID(),
		Severity:       det.Severity(),
		Redacted:       raw.Redacted,
		SourceMetadata: chunk.SourceMetadata,
		Verification: finding.VerificationResult{
			Status: finding.StatusUnverified,
		},
		DetectedAt: e.config.Clock(),
		ExtraData:  raw.ExtraData,
	}
	f.SourceMetadata.Line = lineNum

	if e.config.ShowRaw {
		f.Raw = string(raw.Raw)
	}

	if e.config.EnableEntropy && len(raw.Raw) > 0 {
		f.Entropy = entropy.Calculate(raw.Raw)
	}

	// Deterministic ID: detectorID + redacted + filePath + line + offset.
	// Including the line disambiguates two findings that share the same redacted
	// value in different lines of the same file; including the byte offset
	// further disambiguates two identical matches on the *same* line so they do
	// not collapse onto a single ID.
	hash := sha256.Sum256([]byte(
		det.ID() + raw.Redacted + chunk.SourceMetadata.FilePath +
			strconv.Itoa(lineNum) + ":" + strconv.Itoa(offset),
	))
	f.ID = fmt.Sprintf("%x", hash[:hashTruncateLen])

	return f
}

// applyFilters applies post-scan filters (severity, verification status).
func (e *Engine) applyFilters(findings []finding.Finding) []finding.Finding {
	var result []finding.Finding
	for _, f := range findings {
		if e.config.OnlyVerified && f.Verification.Status != finding.StatusVerifiedActive {
			continue
		}
		if f.Severity < e.config.MinSeverity {
			continue
		}
		result = append(result, f)
	}
	if result == nil {
		return []finding.Finding{}
	}
	return result
}

// sortFindings imposes a single deterministic total order on the final findings
// so output is stable run-to-run regardless of worker scheduling: by file path,
// then line, then detector ID, then redacted value, with the opaque Finding.ID
// as the final tie-breaker.
func sortFindings(findings []finding.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a, b := &findings[i], &findings[j]
		if a.SourceMetadata.FilePath != b.SourceMetadata.FilePath {
			return a.SourceMetadata.FilePath < b.SourceMetadata.FilePath
		}
		if a.SourceMetadata.Line != b.SourceMetadata.Line {
			return a.SourceMetadata.Line < b.SourceMetadata.Line
		}
		if a.DetectorID != b.DetectorID {
			return a.DetectorID < b.DetectorID
		}
		if a.Redacted != b.Redacted {
			return a.Redacted < b.Redacted
		}
		return a.ID < b.ID
	})
}

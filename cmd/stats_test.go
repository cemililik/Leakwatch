package cmd

import (
	"sort"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/meta"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/stretchr/testify/assert"
)

// detectorsAtInit and verifiersAtInit snapshot the registries right after every
// package blank-imported by imports.go has run its init(), before any test can
// mutate the global registries. Capturing here makes the guard below
// independent of test ordering.
var (
	detectorsAtInit []detector.Detector
	verifiersAtInit []verifier.Verifier
)

func init() {
	detectorsAtInit = detector.All()
	verifiersAtInit = verifier.All()
}

// TestCapabilityManifest_MatchesRuntimeRegistries prevents registry count from
// being confused with product capability. Every detector must have exactly one
// manifest entry, and only live/format/context-required entries may have a
// registered verifier.
func TestCapabilityManifest_MatchesRuntimeRegistries(t *testing.T) {
	capabilities := meta.VerificationCapabilities()
	manifestDetectorIDs := make([]string, 0, len(capabilities))
	manifestVerifierIDs := make([]string, 0, meta.Verifiers)
	for _, capability := range capabilities {
		manifestDetectorIDs = append(manifestDetectorIDs, capability.DetectorID)
		if capability.VerifierKind != meta.VerifierNone {
			manifestVerifierIDs = append(manifestVerifierIDs, capability.DetectorID)
		}
	}
	sort.Strings(manifestDetectorIDs)
	sort.Strings(manifestVerifierIDs)

	runtimeDetectorIDs := make([]string, 0, len(detectorsAtInit))
	for _, registered := range detectorsAtInit {
		runtimeDetectorIDs = append(runtimeDetectorIDs, registered.ID())
	}
	runtimeVerifierIDs := make([]string, 0, len(verifiersAtInit))
	for _, registered := range verifiersAtInit {
		runtimeVerifierIDs = append(runtimeVerifierIDs, registered.Type())
	}
	sort.Strings(runtimeDetectorIDs)
	sort.Strings(runtimeVerifierIDs)

	assert.Equal(t, runtimeDetectorIDs, manifestDetectorIDs,
		"capability manifest must classify every registered detector exactly once")
	assert.Equal(t, runtimeVerifierIDs, manifestVerifierIDs,
		"registered verifier IDs must equal all non-none capability entries")
}

// TestMetaCounts_MatchRuntime guards the published counts in internal/meta
// against what the binary actually registers. Every detector and verifier
// package is blank-imported by imports.go in this package, so both registries
// are fully populated here (the detector-only test in internal/detector cannot
// see verifiers, hence the cross-check lives here).
func TestMetaCounts_MatchRuntime(t *testing.T) {
	assert.Len(t, detectorsAtInit, meta.Detectors,
		"meta.Detectors drifted from detector.All(); update internal/meta then run `go generate ./...`")
	assert.Len(t, verifiersAtInit, meta.Verifiers,
		"meta.Verifiers drifted from verifier.All(); update internal/meta then run `go generate ./...`")
}

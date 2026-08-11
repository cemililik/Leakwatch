package cmd

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/internal/meta"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestVerifierContracts_UseRealDetectorOutput proves registry compatibility
// with findings emitted by the production detectors, not hand-assembled
// RawFinding values. It executes each verifier with an already-cancelled
// context: this proves the real finding reaches the declared contract while
// preventing synthetic credentials from reaching provider networks.
func TestVerifierContracts_UseRealDetectorOutput(t *testing.T) {
	fixtures := testutil.RegisteredDetectorFixtures()
	detectors := make(map[string]detector.Detector, len(detectorsAtInit))
	for _, det := range detectorsAtInit {
		detectors[det.ID()] = det
	}
	capabilities := make(map[string]meta.VerificationCapability, len(detectorsAtInit))
	for _, capability := range meta.VerificationCapabilities() {
		capabilities[capability.DetectorID] = capability
	}

	for _, registered := range verifiersAtInit {
		id := registered.Type()
		t.Run(id, func(t *testing.T) {
			capability, ok := capabilities[id]
			require.True(t, ok, "verifier has no capability metadata")
			assert.NotEqual(t, meta.VerifierNone, capability.VerifierKind,
				"registered verifier cannot be categorized as none")

			det, ok := detectors[id]
			require.True(t, ok, "verifier has no registered production detector")
			fixture, ok := fixtures[id]
			require.True(t, ok, "verifier detector has no shared contract fixture")
			findings := testutil.ScanViaMatcher(det, fixture.Input)
			require.NotEmpty(t, findings, "real matcher/detector path produced no verifier input")
			assert.Equal(t, id, findings[0].DetectorID)

			for _, field := range capability.RequiredContextFields {
				if isOperatorSuppliedContext(field) {
					continue
				}
				if field == "raw_v2" {
					assert.NotEmpty(t, findings[0].RawV2,
						"detector must emit required companion field %q", field)
					continue
				}
				assert.NotEmpty(t, findings[0].ExtraData[field],
					"detector must emit required companion field %q", field)
			}

			// Execute the production verifier with an already-cancelled context.
			// Standard HTTP clients and SDKs cannot put the synthetic credential on
			// the wire, while the resulting status proves whether the real detector
			// output actually reached the capability's declared verification path.
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			result := registered.Verify(ctx, findings[0])
			assert.NotContains(t, result.Message, string(findings[0].Raw))
			for key, value := range result.ExtraData {
				assert.NotContains(t, value, string(findings[0].Raw), "ExtraData[%q] leaked fixture credential", key)
			}
			switch capability.VerifierKind {
			case meta.VerifierLive:
				assert.Equal(t, finding.StatusVerifyError, result.Status,
					"live capability must reach its context-cancelled provider request")
			case meta.VerifierFormatOnly:
				assert.Equal(t, finding.StatusUnverified, result.Status)
				assert.True(t, strings.Contains(strings.ToLower(result.Message), "format valid"),
					"format-only fixture must satisfy the production format contract: %s", result.Message)
			case meta.VerifierRequiresContext:
				assert.Equal(t, finding.StatusUnverified, result.Status,
					"missing operator context must fail closed without a request")
			}
		})
	}
}

func isOperatorSuppliedContext(field string) bool {
	switch field {
	case "trusted_api_origin", "trusted_instance_origin", "trusted_store_origin":
		return true
	default:
		return false
	}
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

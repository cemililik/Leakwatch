package meta

import (
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var detectorIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func TestVerificationCapabilities_AreCompleteAndWellFormed(t *testing.T) {
	capabilities := VerificationCapabilities()
	require.Len(t, capabilities, Detectors)

	ids := make([]string, 0, len(capabilities))
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		assert.Regexp(t, detectorIDPattern, capability.DetectorID)
		if _, duplicate := seen[capability.DetectorID]; duplicate {
			t.Errorf("duplicate capability for detector %q", capability.DetectorID)
		}
		seen[capability.DetectorID] = struct{}{}
		ids = append(ids, capability.DetectorID)

		switch capability.VerifierKind {
		case VerifierLive:
			assert.NotEqual(t, "none", capability.EndpointClass, capability.DetectorID)
			assert.NotEqual(t, "none", capability.InactiveStatusContract, capability.DetectorID)
		case VerifierFormatOnly:
			assert.Equal(t, "offline_format", capability.EndpointClass, capability.DetectorID)
			assert.Equal(t, "none", capability.InactiveStatusContract, capability.DetectorID)
		case VerifierRequiresContext:
			assert.NotEmpty(t, capability.RequiredContextFields, capability.DetectorID)
			assert.NotEqual(t, "none", capability.EndpointClass, capability.DetectorID)
			assert.NotEqual(t, "none", capability.InactiveStatusContract, capability.DetectorID)
		case VerifierNone:
			assert.Equal(t, "none", capability.EndpointClass, capability.DetectorID)
			assert.Equal(t, "none", capability.InactiveStatusContract, capability.DetectorID)
		default:
			t.Errorf("detector %q has unknown verifier kind %q", capability.DetectorID, capability.VerifierKind)
		}

		if capability.LastContractReviewedAt != "" {
			_, err := time.Parse(time.DateOnly, capability.LastContractReviewedAt)
			assert.NoError(t, err, capability.DetectorID)
		}
	}

	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	assert.Equal(t, sorted, ids, "capability manifest must remain sorted by detector ID")
}

func TestVerificationCapabilityCounts_MatchPublishedCategories(t *testing.T) {
	counts := VerificationCapabilityCounts()
	assert.Equal(t, CapabilityCounts{Live: 45, FormatOnly: 6, RequiresContext: 3, None: 11}, counts)
	assert.Equal(t, Detectors, counts.Live+counts.FormatOnly+counts.RequiresContext+counts.None)
	assert.Equal(t, Verifiers, counts.Live+counts.FormatOnly+counts.RequiresContext,
		"every non-none capability has one registered verifier")
}

func TestVerificationCapabilities_ReturnsDefensiveCopy(t *testing.T) {
	first := VerificationCapabilities()
	require.NotEmpty(t, first)
	originalID := first[0].DetectorID
	contextIndex, regionIndex := -1, -1
	for i := range first {
		if contextIndex < 0 && len(first[i].RequiredContextFields) > 0 {
			contextIndex = i
		}
		if regionIndex < 0 && len(first[i].ProviderRegions) > 0 {
			regionIndex = i
		}
	}
	require.NotEqual(t, -1, contextIndex)
	require.NotEqual(t, -1, regionIndex)
	originalContext := first[contextIndex].RequiredContextFields[0]
	originalRegion := first[regionIndex].ProviderRegions[0]
	first[0].DetectorID = "mutated"
	first[contextIndex].RequiredContextFields[0] = "mutated"
	first[regionIndex].ProviderRegions[0] = "mutated"

	second := VerificationCapabilities()
	assert.Equal(t, originalID, second[0].DetectorID)
	assert.Equal(t, originalContext, second[contextIndex].RequiredContextFields[0])
	assert.Equal(t, originalRegion, second[regionIndex].ProviderRegions[0])
}

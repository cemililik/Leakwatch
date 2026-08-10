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

var validEndpointClasses = map[EndpointClass]struct{}{
	EndpointNone: {}, EndpointOfflineFormat: {}, EndpointFixedProviderAPI: {},
	EndpointFixedProviderSDK: {}, EndpointRegionalProviderAPI: {},
	EndpointBoundedRegionalProviderAPI: {}, EndpointIssuerDerivedProviderAPI: {},
	EndpointDetectorContextProviderAPI: {}, EndpointDetectorContextOrPublicAPI: {},
	EndpointOperatorContextProviderAPI: {}, EndpointCompanionContextProviderAPI: {},
	EndpointCompanionContextFixedAPI: {}, EndpointEmbeddedProviderURL: {},
}

var validInactiveContracts = map[InactiveStatusContract]struct{}{
	InactiveNone: {}, InactiveDefinitiveAuthRejection: {}, InactiveHTTP401Only: {},
	InactiveAllRegionsHTTP401: {}, InactiveRegionAppropriateRejection: {},
	InactiveProviderBodyRejection: {}, InactiveProviderSpecificRejection: {},
	InactivePairedAuthRejection: {}, InactiveTrustedInstanceHTTP401: {},
	InactiveTrustedIssuerHTTP401: {}, InactiveTrustedOriginHTTP401: {},
	InactiveTrustedOriginRejection: {},
	InactiveTrustedSiteRejection:   {}, InactiveTrustedStoreRejection: {},
	InactiveTypedAuthenticationError: {},
}

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
		assert.Contains(t, validEndpointClasses, capability.EndpointClass, capability.DetectorID)
		assert.Contains(t, validInactiveContracts, capability.InactiveStatusContract, capability.DetectorID)

		switch capability.VerifierKind {
		case VerifierLive:
			assert.NotEqual(t, EndpointNone, capability.EndpointClass, capability.DetectorID)
			assert.NotEqual(t, InactiveNone, capability.InactiveStatusContract, capability.DetectorID)
		case VerifierFormatOnly:
			assert.Empty(t, capability.RequiredContextFields, capability.DetectorID)
			assert.Equal(t, EndpointOfflineFormat, capability.EndpointClass, capability.DetectorID)
			assert.Equal(t, InactiveNone, capability.InactiveStatusContract, capability.DetectorID)
		case VerifierRequiresContext:
			assert.NotEmpty(t, capability.RequiredContextFields, capability.DetectorID)
			assert.NotEqual(t, EndpointNone, capability.EndpointClass, capability.DetectorID)
			assert.NotEqual(t, InactiveNone, capability.InactiveStatusContract, capability.DetectorID)
		case VerifierNone:
			assert.Empty(t, capability.RequiredContextFields, capability.DetectorID)
			assert.Equal(t, EndpointNone, capability.EndpointClass, capability.DetectorID)
			assert.Equal(t, InactiveNone, capability.InactiveStatusContract, capability.DetectorID)
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
	assert.Equal(t, CapabilityCounts{Live: 41, FormatOnly: 6, RequiresContext: 7, None: 11}, counts)
	assert.Equal(t, Detectors, counts.Live+counts.FormatOnly+counts.RequiresContext+counts.None)
	assert.Equal(t, Verifiers, counts.Live+counts.FormatOnly+counts.RequiresContext,
		"every non-none capability has one registered verifier")
}

func TestVerificationCapabilities_ReturnsDefensiveCopy(t *testing.T) {
	first := VerificationCapabilities()
	require.NotEmpty(t, first)
	originalID := first[0].DetectorID
	contextIndex, regionIndex, subtypeIndex := -1, -1, -1
	for i := range first {
		if contextIndex < 0 && len(first[i].RequiredContextFields) > 0 {
			contextIndex = i
		}
		if regionIndex < 0 && len(first[i].ProviderRegions) > 0 {
			regionIndex = i
		}
		if subtypeIndex < 0 && len(first[i].VerifiableSubtypes) > 0 && len(first[i].UnverifiableSubtypes) > 0 {
			subtypeIndex = i
		}
	}
	require.NotEqual(t, -1, contextIndex)
	require.NotEqual(t, -1, regionIndex)
	require.NotEqual(t, -1, subtypeIndex)
	originalContext := first[contextIndex].RequiredContextFields[0]
	originalRegion := first[regionIndex].ProviderRegions[0]
	originalVerifiableSubtype := first[subtypeIndex].VerifiableSubtypes[0]
	originalUnverifiableSubtype := first[subtypeIndex].UnverifiableSubtypes[0]
	first[0].DetectorID = "mutated"
	first[contextIndex].RequiredContextFields[0] = "mutated"
	first[regionIndex].ProviderRegions[0] = "mutated"
	first[subtypeIndex].VerifiableSubtypes[0] = "mutated"
	first[subtypeIndex].UnverifiableSubtypes[0] = "mutated"

	second := VerificationCapabilities()
	assert.Equal(t, originalID, second[0].DetectorID)
	assert.Equal(t, originalContext, second[contextIndex].RequiredContextFields[0])
	assert.Equal(t, originalRegion, second[regionIndex].ProviderRegions[0])
	assert.Equal(t, originalVerifiableSubtype, second[subtypeIndex].VerifiableSubtypes[0])
	assert.Equal(t, originalUnverifiableSubtype, second[subtypeIndex].UnverifiableSubtypes[0])
}

func TestVerificationCapabilities_GitHubOAuthSubtypeContract(t *testing.T) {
	for _, capability := range VerificationCapabilities() {
		if capability.DetectorID != "github-oauth-token" {
			continue
		}
		assert.Equal(t, []string{"gho", "ghu", "ghs"}, capability.VerifiableSubtypes)
		assert.Equal(t, []string{"ghr"}, capability.UnverifiableSubtypes)
		return
	}
	t.Fatal("github-oauth-token capability missing")
}

func TestVerificationCapabilities_SnykInactiveContractIsTrustedOrigin401Only(t *testing.T) {
	for _, capability := range VerificationCapabilities() {
		if capability.DetectorID != "snyk-api-key" {
			continue
		}
		assert.Equal(t, InactiveTrustedOriginHTTP401, capability.InactiveStatusContract)
		return
	}
	t.Fatal("snyk-api-key capability missing")
}

func TestVerificationCapabilities_CriticalContextContracts(t *testing.T) {
	want := map[string]struct {
		kind    VerifierKind
		fields  []string
		regions []string
	}{
		"aws-access-key-id":    {VerifierLive, []string{"raw_v2"}, nil},
		"databricks-token":     {VerifierLive, []string{"host"}, nil},
		"okta-api-token":       {VerifierLive, []string{"domain"}, nil},
		"datadog-api-key":      {VerifierRequiresContext, []string{"trusted_api_origin"}, []string{"US1", "US3", "US5", "EU", "AP1", "AP2", "UK1", "US1-FED", "US2-FED"}},
		"github-token":         {VerifierRequiresContext, []string{"trusted_api_origin"}, []string{"GitHub.com", "GHES"}},
		"github-oauth-token":   {VerifierRequiresContext, []string{"trusted_api_origin"}, []string{"GitHub.com", "GHES"}},
		"snyk-api-key":         {VerifierRequiresContext, []string{"trusted_api_origin"}, []string{"US1", "US2", "EU", "AU", "GOV", "PRIVATE"}},
		"grafana-api-key":      {VerifierRequiresContext, []string{"trusted_instance_origin"}, nil},
		"shopify-access-token": {VerifierRequiresContext, []string{"store_domain"}, nil},
		"twilio-api-key":       {VerifierRequiresContext, []string{"account_sid", "api_key_secret"}, nil},
	}

	got := make(map[string]VerificationCapability, len(want))
	for _, capability := range VerificationCapabilities() {
		if _, tracked := want[capability.DetectorID]; tracked {
			got[capability.DetectorID] = capability
		}
	}
	require.Len(t, got, len(want))
	for detectorID, expected := range want {
		capability := got[detectorID]
		assert.Equal(t, expected.kind, capability.VerifierKind, detectorID)
		assert.Equal(t, expected.fields, capability.RequiredContextFields, detectorID)
		assert.Equal(t, expected.regions, capability.ProviderRegions, detectorID)
	}
}

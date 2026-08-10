package meta

// VerifierKind describes what a detector can truthfully prove in the normal
// production pipeline. It is deliberately independent of registry presence:
// a registered verifier may still need context the detector cannot supply, or
// may perform only offline format validation.
type VerifierKind string

const (
	VerifierLive            VerifierKind = "live"
	VerifierFormatOnly      VerifierKind = "format_only"
	VerifierRequiresContext VerifierKind = "requires_context"
	VerifierNone            VerifierKind = "none"
)

// EndpointClass describes how a verifier selects the endpoint that receives a
// credential. Values are closed and validated in tests so a typo cannot
// silently create a new routing contract.
type EndpointClass string

const (
	EndpointNone                        EndpointClass = "none"
	EndpointOfflineFormat               EndpointClass = "offline_format"
	EndpointFixedProviderAPI            EndpointClass = "fixed_provider_api"
	EndpointFixedProviderSDK            EndpointClass = "fixed_provider_sdk"
	EndpointRegionalProviderAPI         EndpointClass = "regional_provider_api"
	EndpointBoundedRegionalProviderAPI  EndpointClass = "bounded_regional_provider_api"
	EndpointIssuerDerivedProviderAPI    EndpointClass = "issuer_derived_provider_api"
	EndpointDetectorContextProviderAPI  EndpointClass = "detector_context_provider_api"
	EndpointDetectorContextOrPublicAPI  EndpointClass = "detector_context_or_public_provider_api"
	EndpointOperatorContextProviderAPI  EndpointClass = "operator_context_provider_api"
	EndpointCompanionContextProviderAPI EndpointClass = "companion_context_provider_api"
	EndpointCompanionContextFixedAPI    EndpointClass = "companion_context_fixed_provider_api"
	EndpointEmbeddedProviderURL         EndpointClass = "credential_embedded_provider_url"
)

// InactiveStatusContract identifies the exact class of evidence that may
// produce verified_inactive. It is deliberately distinct from EndpointClass.
type InactiveStatusContract string

const (
	InactiveNone                       InactiveStatusContract = "none"
	InactiveDefinitiveAuthRejection    InactiveStatusContract = "definitive_provider_auth_rejection"
	InactiveHTTP401Only                InactiveStatusContract = "http_401_only"
	InactiveAllRegionsHTTP401          InactiveStatusContract = "all_regions_http_401"
	InactiveRegionAppropriateRejection InactiveStatusContract = "region_appropriate_auth_rejection"
	InactiveProviderBodyRejection      InactiveStatusContract = "provider_body_auth_rejection"
	InactiveProviderSpecificRejection  InactiveStatusContract = "provider_specific_definitive_rejection"
	InactivePairedAuthRejection        InactiveStatusContract = "paired_credential_auth_rejection"
	InactiveTrustedInstanceHTTP401     InactiveStatusContract = "trusted_instance_http_401"
	InactiveTrustedIssuerHTTP401       InactiveStatusContract = "trusted_issuer_http_401"
	InactiveTrustedOriginHTTP401       InactiveStatusContract = "trusted_origin_http_401"
	InactiveTrustedOriginRejection     InactiveStatusContract = "trusted_origin_auth_rejection"
	InactiveTrustedSiteRejection       InactiveStatusContract = "trusted_site_auth_rejection"
	InactiveTrustedStoreHTTP401        InactiveStatusContract = "trusted_store_http_401"
	InactiveTrustedStoreRejection      InactiveStatusContract = "trusted_store_auth_rejection"
	InactiveTypedAuthenticationError   InactiveStatusContract = "typed_authentication_error"
)

// VerificationCapability is the canonical machine-readable contract for one
// built-in detector. Empty ProviderRegions means the provider exposes one
// global endpoint class or the region is encoded by trusted credential context.
// LastContractReviewedAt is intentionally empty until the provider contract has
// been checked against current primary documentation; an empty value must never
// be presented as a completed audit.
type VerificationCapability struct {
	DetectorID             string
	VerifierKind           VerifierKind
	RequiredContextFields  []string
	ProviderRegions        []string
	VerifiableSubtypes     []string
	UnverifiableSubtypes   []string
	EndpointClass          EndpointClass
	InactiveStatusContract InactiveStatusContract
	LastContractReviewedAt string
}

// verificationCapabilities is sorted by detector ID. Keep entries compact and
// factual: provider-specific prose belongs in user documentation, while this
// manifest owns categorization, routing class, and inactive-proof semantics.
var verificationCapabilities = []VerificationCapability{
	{DetectorID: "airtable-pat", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "anthropic-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "auth0-management-token", VerifierKind: VerifierLive, EndpointClass: "issuer_derived_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "aws-access-key-id", VerifierKind: VerifierLive, RequiredContextFields: []string{"raw_v2"}, EndpointClass: "fixed_provider_sdk", InactiveStatusContract: "typed_authentication_error"},
	{DetectorID: "azure-entra-secret", VerifierKind: VerifierFormatOnly, EndpointClass: "offline_format", InactiveStatusContract: "none"},
	{DetectorID: "azure-storage-key", VerifierKind: VerifierFormatOnly, EndpointClass: "offline_format", InactiveStatusContract: "none"},
	{DetectorID: "bitbucket-app-password", VerifierKind: VerifierLive, RequiredContextFields: []string{"username"}, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "circleci-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "cloudflare-api-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "coinbase-api-key", VerifierKind: VerifierFormatOnly, EndpointClass: "offline_format", InactiveStatusContract: "none"},
	{DetectorID: "database-connection-string", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "databricks-token", VerifierKind: VerifierLive, RequiredContextFields: []string{"host"}, EndpointClass: "detector_context_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "datadog-api-key", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"trusted_api_origin"}, ProviderRegions: []string{"US1", "US3", "US5", "EU", "AP1", "AP2", "UK1", "US1-FED", "US2-FED"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_site_auth_rejection", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "deepseek-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "digitalocean-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "discord-bot-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "discord-webhook-url", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "dockerhub-pat", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "doppler-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "figma-pat", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "ftp-credentials", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "gcp-service-account", VerifierKind: VerifierFormatOnly, EndpointClass: "offline_format", InactiveStatusContract: "none"},
	{DetectorID: "generic-api-key", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "github-oauth-token", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"trusted_api_origin"}, ProviderRegions: []string{"GitHub.com", "GHES"}, VerifiableSubtypes: []string{"gho", "ghu", "ghs"}, UnverifiableSubtypes: []string{"ghr"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_issuer_http_401", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "github-token", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"trusted_api_origin"}, ProviderRegions: []string{"GitHub.com", "GHES"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_issuer_http_401", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "gitlab-pat", VerifierKind: VerifierLive, EndpointClass: "detector_context_or_public_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "grafana-api-key", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"trusted_instance_origin"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_instance_http_401", LastContractReviewedAt: "2026-08-10"},
	{DetectorID: "hashicorp-vault-token", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "heroku-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "huggingface-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "infura-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "jwt", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "launchdarkly-sdk-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "ldap-credentials", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "linear-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "mailgun-api-key", VerifierKind: VerifierLive, ProviderRegions: []string{"US", "EU"}, EndpointClass: "regional_provider_api", InactiveStatusContract: "region_appropriate_auth_rejection"},
	{DetectorID: "newrelic-api-key", VerifierKind: VerifierLive, ProviderRegions: []string{"US", "EU"}, EndpointClass: "bounded_regional_provider_api", InactiveStatusContract: "all_regions_http_401", LastContractReviewedAt: "2026-08-10"},
	{DetectorID: "notion-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "npm-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "okta-api-token", VerifierKind: VerifierLive, RequiredContextFields: []string{"domain"}, EndpointClass: "detector_context_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "openai-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "pagerduty-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "postmark-server-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "private-key", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "pypi-api-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "rabbitmq-connection-string", VerifierKind: VerifierFormatOnly, EndpointClass: "offline_format", InactiveStatusContract: "none"},
	{DetectorID: "redis-connection-string", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "rubygems-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "sendgrid-api-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "http_401_only"},
	{DetectorID: "sentry-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "shopify-access-token", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"trusted_store_origin"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_store_http_401", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "slack-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "provider_body_auth_rejection"},
	{DetectorID: "slack-webhook", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "snowflake-credentials", VerifierKind: VerifierFormatOnly, EndpointClass: "offline_format", InactiveStatusContract: "none"},
	{DetectorID: "snyk-api-key", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"trusted_api_origin"}, ProviderRegions: []string{"US1", "US2", "EU", "AU", "GOV", "PRIVATE"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_origin_http_401", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "sonarcloud-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "stripe-api-key-live", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "stripe-api-key-test", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "structured-config-secret", VerifierKind: VerifierNone, EndpointClass: "none", InactiveStatusContract: "none"},
	{DetectorID: "supabase-service-key", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "http_401_only", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "teams-webhook", VerifierKind: VerifierLive, EndpointClass: "credential_embedded_provider_url", InactiveStatusContract: "provider_specific_definitive_rejection"},
	{DetectorID: "telegram-bot-token", VerifierKind: VerifierLive, EndpointClass: "credential_embedded_provider_url", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "terraform-cloud-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
	{DetectorID: "twilio-api-key", VerifierKind: VerifierRequiresContext, RequiredContextFields: []string{"api_key_sid", "trusted_api_origin"}, ProviderRegions: []string{"US1", "IE1", "AU1"}, EndpointClass: "operator_context_provider_api", InactiveStatusContract: "trusted_origin_http_401", LastContractReviewedAt: "2026-08-11"},
	{DetectorID: "vercel-token", VerifierKind: VerifierLive, EndpointClass: "fixed_provider_api", InactiveStatusContract: "definitive_provider_auth_rejection"},
}

// VerificationCapabilities returns a deep copy so callers cannot mutate the
// canonical manifest or any of its context/region slices.
func VerificationCapabilities() []VerificationCapability {
	out := make([]VerificationCapability, len(verificationCapabilities))
	for i, capability := range verificationCapabilities {
		out[i] = capability
		out[i].RequiredContextFields = append([]string(nil), capability.RequiredContextFields...)
		out[i].ProviderRegions = append([]string(nil), capability.ProviderRegions...)
		out[i].VerifiableSubtypes = append([]string(nil), capability.VerifiableSubtypes...)
		out[i].UnverifiableSubtypes = append([]string(nil), capability.UnverifiableSubtypes...)
	}
	return out
}

// CapabilityCounts summarizes the canonical manifest by verifier kind.
type CapabilityCounts struct {
	Live            int
	FormatOnly      int
	RequiresContext int
	None            int
}

// VerificationCapabilityCounts returns the current category totals.
func VerificationCapabilityCounts() CapabilityCounts {
	var counts CapabilityCounts
	for _, capability := range verificationCapabilities {
		switch capability.VerifierKind {
		case VerifierLive:
			counts.Live++
		case VerifierFormatOnly:
			counts.FormatOnly++
		case VerifierRequiresContext:
			counts.RequiresContext++
		case VerifierNone:
			counts.None++
		}
	}
	return counts
}

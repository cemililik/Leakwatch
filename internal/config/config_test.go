package config

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestViper() *viper.Viper {
	return viper.New()
}

func TestLoadFrom_NoOverrides_ReturnsDefaults(t *testing.T) {
	v := newTestViper()

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.Equal(t, runtime.NumCPU(), cfg.Scan.Concurrency)
	assert.Equal(t, int64(10*1024*1024), cfg.Scan.MaxFileSize)
	assert.True(t, cfg.Detection.Entropy.Enabled)
	assert.Equal(t, 4.0, cfg.Detection.Entropy.Threshold)
	assert.Equal(t, "json", cfg.Output.Format)
	assert.False(t, cfg.Output.ShowRaw)

	// Verification defaults.
	assert.True(t, cfg.Verification.Enabled)
	assert.Equal(t, 10*time.Second, cfg.Verification.Timeout)
	assert.Equal(t, 4, cfg.Verification.Concurrency)
	assert.Equal(t, 10.0, cfg.Verification.RateLimit)

	// No custom rules by default.
	assert.Empty(t, cfg.CustomRules)
}

func TestLoadFrom_VerificationOverrides_Applied(t *testing.T) {
	v := newTestViper()
	v.Set("verification.enabled", false)
	v.Set("verification.timeout", "30s")
	v.Set("verification.concurrency", 8)
	v.Set("verification.rate-limit", 25.0)

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.False(t, cfg.Verification.Enabled)
	assert.Equal(t, 30*time.Second, cfg.Verification.Timeout)
	assert.Equal(t, 8, cfg.Verification.Concurrency)
	assert.Equal(t, 25.0, cfg.Verification.RateLimit)
}

func TestLoadFrom_InvalidVerificationTimeout_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("verification.timeout", "0s")

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification timeout")
}

func TestLoadFrom_DisabledVerificationSkipsValidation(t *testing.T) {
	// A disabled verification block with leftover non-positive values must still
	// load (the values are inert), preserving backward compatibility.
	v := newTestViper()
	v.Set("verification.enabled", false)
	v.Set("verification.timeout", "0s")
	v.Set("verification.concurrency", 0)
	v.Set("verification.rate-limit", 0.0)

	cfg, err := LoadFrom(v)
	require.NoError(t, err)
	assert.False(t, cfg.Verification.Enabled)
}

func TestLoadFrom_UnitlessTimeoutRejected(t *testing.T) {
	// A bare number decodes as nanoseconds (30 -> 30ns); the minimum-timeout
	// guard rejects it so users don't silently get a 30ns timeout.
	v := newTestViper()
	v.Set("verification.timeout", 30)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification timeout")
}

func TestLoadFrom_InvalidSeverityThreshold_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("output.severity-threshold", "criticla") // typo

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "severity-threshold")
}

func TestLoadFrom_ValidSeverityThreshold_Accepted(t *testing.T) {
	for _, sev := range []string{"low", "medium", "high", "critical"} {
		v := newTestViper()
		v.Set("output.severity-threshold", sev)
		cfg, err := LoadFrom(v)
		require.NoError(t, err, "severity %q should be valid", sev)
		assert.Equal(t, sev, cfg.Output.SeverityThreshold)
	}
}

func TestLoadFrom_InvalidVerificationConcurrency_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("verification.concurrency", 0)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification concurrency")
}

func TestLoadFrom_InvalidVerificationRateLimit_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("verification.rate-limit", 0.0)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification rate-limit")
}

func TestLoadFrom_FilterAndOutputExtras_Unmarshalled(t *testing.T) {
	v := newTestViper()
	v.Set("filter.exclude-detectors", []string{"generic-api-key", "jwt"})
	v.Set("output.severity-threshold", "high")

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.Equal(t, []string{"generic-api-key", "jwt"}, cfg.Filter.ExcludeDetectors)
	assert.Equal(t, "high", cfg.Output.SeverityThreshold)
}

func TestLoadFrom_FilterExcludePaths_Unmarshalled(t *testing.T) {
	// filter.exclude-paths must be registered with Viper's default set (like
	// filter.exclude-detectors) so that AutomaticEnv/Set overrides for this key
	// actually reach the unmarshalled Config; a missing SetDefault silently
	// drops the value.
	v := newTestViper()
	v.Set("filter.exclude-paths", []string{"vendor/**", "*.lock"})

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.Equal(t, []string{"vendor/**", "*.lock"}, cfg.Filter.ExcludePaths)
}

func TestLoadFrom_FilterExcludePaths_DefaultsEmpty(t *testing.T) {
	v := newTestViper()

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.Empty(t, cfg.Filter.ExcludePaths)
}

func TestLoadFrom_FilterExcludePathsEnvVar_Honored(t *testing.T) {
	// Regression test for the documented "every config key can be overridden
	// with an environment variable" contract: LEAKWATCH_FILTER_EXCLUDE_PATHS
	// must reach Config.Filter.ExcludePaths. This mirrors the AutomaticEnv
	// wiring cmd/scan_common.go performs on its own Viper instance, without
	// depending on cmd/ (out of scope for this package's tests).
	t.Setenv("LEAKWATCH_FILTER_EXCLUDE_PATHS", "vendor/**,*.lock")

	v := newTestViper()
	v.SetEnvPrefix("LEAKWATCH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.Equal(t, []string{"vendor/**", "*.lock"}, cfg.Filter.ExcludePaths)
}

func TestLoadFrom_CustomRules_Unmarshalled(t *testing.T) {
	v := newTestViper()
	v.Set("custom-rules", []map[string]any{
		{
			"id":          "internal-token",
			"description": "Internal Service Token",
			"regex":       "INT_[A-Za-z0-9]{32}",
			"keywords":    []string{"INT_"},
			"severity":    "high",
			"entropy":     3.5,
		},
	})

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	require.Len(t, cfg.CustomRules, 1)
	rule := cfg.CustomRules[0]
	assert.Equal(t, "internal-token", rule.ID)
	assert.Equal(t, "Internal Service Token", rule.Description)
	assert.Equal(t, "INT_[A-Za-z0-9]{32}", rule.Regex)
	assert.Equal(t, []string{"INT_"}, rule.Keywords)
	assert.Equal(t, "high", rule.Severity)
	assert.InEpsilon(t, 3.5, rule.Entropy, 0.0001)
}

func TestLoadFrom_CustomValues_OverridesDefaults(t *testing.T) {
	v := newTestViper()
	v.Set("scan.concurrency", 4)
	v.Set("scan.max-file-size", 5*1024*1024)

	cfg, err := LoadFrom(v)
	require.NoError(t, err)

	assert.Equal(t, 4, cfg.Scan.Concurrency)
	assert.Equal(t, int64(5*1024*1024), cfg.Scan.MaxFileSize)
}

func TestLoadFrom_InvalidConcurrency_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("scan.concurrency", 0)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "concurrency")
}

func TestLoadFrom_InvalidMaxFileSize_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("scan.max-file-size", -1)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max-file-size")
}

func TestLoadFrom_MaxFileSizeAboveCeiling_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("scan.max-file-size", maxFileSizeCeiling+1)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max-file-size")
}

func TestLoadFrom_MaxFileSizeAtCeiling_Accepted(t *testing.T) {
	v := newTestViper()
	v.Set("scan.max-file-size", maxFileSizeCeiling)

	cfg, err := LoadFrom(v)
	require.NoError(t, err)
	assert.Equal(t, int64(maxFileSizeCeiling), cfg.Scan.MaxFileSize)
}

func TestLoadFrom_UnsupportedFormat_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("output.format", "xml")

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

func TestLoadFrom_InvalidEntropyThreshold_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("detection.entropy.threshold", 9.0)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entropy threshold")
}

func TestLoadFrom_NegativeEntropyThreshold_ReturnsError(t *testing.T) {
	v := newTestViper()
	v.Set("detection.entropy.threshold", -1.0)

	_, err := LoadFrom(v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entropy threshold")
}

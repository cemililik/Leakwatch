// Package config provides Leakwatch configuration management.
package config

import (
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/viper"

	"github.com/HodeTech/leakwatch/internal/detector/custom"
	"github.com/HodeTech/leakwatch/internal/meta"
)

// Supported severity levels for output.severity-threshold.
var validSeverities = map[string]bool{
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

// minVerificationTimeout is the smallest accepted verification timeout. It
// guards against a bare number in YAML (e.g. `timeout: 30`) being silently
// decoded as 30 nanoseconds instead of the intended duration.
const minVerificationTimeout = time.Millisecond

// maxFileSizeCeiling bounds the largest single file Leakwatch will read into
// memory during a scan. Every source (filesystem, git, container, s3, gcs)
// fully buffers a file/blob/object up to scan.max-file-size in one []byte per
// in-flight job, so an unbounded limit lets a misconfiguration hold many
// multi-gigabyte buffers in memory simultaneously (concurrency * 2 in-flight
// jobs). 1GB comfortably covers legitimate large-file use cases while keeping
// worst-case memory usage bounded.
const maxFileSizeCeiling = 1 * 1024 * 1024 * 1024 // 1GB

// Config represents the complete application configuration.
type Config struct {
	Scan         ScanConfig         `mapstructure:"scan"`
	Detection    DetectionConfig    `mapstructure:"detection"`
	Verification VerificationConfig `mapstructure:"verification"`
	Filter       FilterConfig       `mapstructure:"filter"`
	Output       OutputConfig       `mapstructure:"output"`
	CustomRules  []custom.RuleDef   `mapstructure:"custom-rules"`
}

// ScanConfig holds scan engine configuration.
type ScanConfig struct {
	Concurrency int   `mapstructure:"concurrency"`
	MaxFileSize int64 `mapstructure:"max-file-size"`
}

// DetectionConfig holds detection configuration.
type DetectionConfig struct {
	Entropy EntropyConfig `mapstructure:"entropy"`
}

// EntropyConfig holds entropy analysis configuration.
type EntropyConfig struct {
	Enabled   bool    `mapstructure:"enabled"`
	Threshold float64 `mapstructure:"threshold"`
}

// VerificationConfig holds secret verification configuration.
type VerificationConfig struct {
	Enabled     bool          `mapstructure:"enabled"`
	Timeout     time.Duration `mapstructure:"timeout"`
	Concurrency int           `mapstructure:"concurrency"`
	RateLimit   float64       `mapstructure:"rate-limit"`
}

// FilterConfig holds filtering configuration.
type FilterConfig struct {
	ExcludePaths     []string `mapstructure:"exclude-paths"`
	ExcludeDetectors []string `mapstructure:"exclude-detectors"`
}

// OutputConfig holds output configuration.
type OutputConfig struct {
	Format            string `mapstructure:"format"`
	File              string `mapstructure:"file"`
	SeverityThreshold string `mapstructure:"severity-threshold"`
	ShowRaw           bool   `mapstructure:"show-raw"`
}

// setDefaults configures default values on the given Viper instance.
func setDefaults(v *viper.Viper) {
	v.SetDefault("scan.concurrency", runtime.NumCPU())
	v.SetDefault("scan.max-file-size", 10*1024*1024) // 10MB
	v.SetDefault("detection.entropy.enabled", true)
	v.SetDefault("detection.entropy.threshold", 4.0)
	v.SetDefault("verification.enabled", true)
	v.SetDefault("verification.timeout", 10*time.Second)
	v.SetDefault("verification.concurrency", 4)
	v.SetDefault("verification.rate-limit", 10.0)
	v.SetDefault("output.format", "json")
	v.SetDefault("output.show-raw", false)
	// Empty defaults register these keys with Viper so AutomaticEnv override
	// works through Unmarshal (Viper only reads env vars for keys it knows
	// about). The empty values keep behavior unchanged when nothing is set.
	v.SetDefault("output.severity-threshold", "")
	v.SetDefault("filter.exclude-detectors", []string{})
	v.SetDefault("filter.exclude-paths", []string{})
}

// LoadFrom reads configuration from a specific Viper instance and returns a
// validated Config. Each scan command builds its own isolated Viper (see
// cmd/scan_common.go) and passes it here, which keeps one command's bound flag
// defaults from leaking into another command's resolved configuration.
func LoadFrom(v *viper.Viper) (*Config, error) {
	setDefaults(v)
	return unmarshalAndValidate(v)
}

func unmarshalAndValidate(v *viper.Viper) (*Config, error) {
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Scan.Concurrency < 1 {
		return fmt.Errorf("invalid concurrency value: %d", c.Scan.Concurrency)
	}
	if c.Scan.MaxFileSize < 1 {
		return fmt.Errorf("invalid max-file-size value: %d", c.Scan.MaxFileSize)
	}
	if c.Scan.MaxFileSize > maxFileSizeCeiling {
		return fmt.Errorf("invalid max-file-size value: %d exceeds maximum of %d bytes (%dMB); per-file scanning is fully in-memory, so raising this limit risks large per-job memory usage", c.Scan.MaxFileSize, maxFileSizeCeiling, maxFileSizeCeiling/(1024*1024))
	}
	if !meta.IsOutputFormat(c.Output.Format) {
		return fmt.Errorf("unsupported output format: %s", c.Output.Format)
	}
	if c.Detection.Entropy.Threshold < 0 || c.Detection.Entropy.Threshold > 8.0 {
		return fmt.Errorf("invalid entropy threshold: %.2f (must be 0-8)", c.Detection.Entropy.Threshold)
	}
	if c.Output.SeverityThreshold != "" && !validSeverities[c.Output.SeverityThreshold] {
		return fmt.Errorf("invalid output severity-threshold: %q (must be low, medium, high, or critical)", c.Output.SeverityThreshold)
	}
	// Verification settings are only enforced when verification is enabled, so a
	// disabled block with leftover non-positive values still loads.
	if c.Verification.Enabled {
		if c.Verification.Timeout < minVerificationTimeout {
			return fmt.Errorf("invalid verification timeout: %s (must be >= %s; a bare number is interpreted as nanoseconds, use a unit like \"10s\")", c.Verification.Timeout, minVerificationTimeout)
		}
		if c.Verification.Concurrency < 1 {
			return fmt.Errorf("invalid verification concurrency: %d (must be >= 1)", c.Verification.Concurrency)
		}
		if c.Verification.RateLimit <= 0 {
			return fmt.Errorf("invalid verification rate-limit: %.2f (must be positive)", c.Verification.RateLimit)
		}
	}
	return nil
}

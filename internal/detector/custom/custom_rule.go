// Package custom provides a YAML-based custom rule detector.
// Users can define their own secret patterns in .leakwatch.yaml.
package custom

import (
	"bytes"
	"context"
	"fmt"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/entropy"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// maxRegexLength is the maximum allowed length of a custom rule regex pattern.
const maxRegexLength = 4096

// RuleDef represents a user-defined custom detection rule from YAML config.
type RuleDef struct {
	ID          string   `yaml:"id" mapstructure:"id"`
	Description string   `yaml:"description" mapstructure:"description"`
	Regex       string   `yaml:"regex" mapstructure:"regex"`
	Keywords    []string `yaml:"keywords" mapstructure:"keywords"`
	Severity    string   `yaml:"severity" mapstructure:"severity"`
	Entropy     float64  `yaml:"entropy" mapstructure:"entropy"`
}

// CustomDetector implements detector.Detector for user-defined rules.
type CustomDetector struct {
	def     RuleDef
	pattern *regexp.Regexp
	sev     finding.Severity
}

// NewFromDef creates a CustomDetector from a RuleDef.
// Returns an error if the regex pattern is invalid or exceeds the maximum length.
func NewFromDef(def RuleDef) (*CustomDetector, error) {
	if def.ID == "" {
		return nil, fmt.Errorf("custom rule ID is required")
	}
	if def.Regex == "" {
		return nil, fmt.Errorf("custom rule %q: regex is required", def.ID)
	}
	if len(def.Regex) > maxRegexLength {
		return nil, fmt.Errorf("custom rule %q: regex length %d exceeds maximum %d", def.ID, len(def.Regex), maxRegexLength)
	}

	pattern, err := regexp.Compile(def.Regex)
	if err != nil {
		return nil, fmt.Errorf("custom rule %q: invalid regex: %w", def.ID, err)
	}

	// An empty severity legitimately defaults to medium; a non-empty but
	// unrecognized severity (a casing mistake like "Critical", or a typo like
	// "critial") must fail loudly rather than being silently downgraded to
	// medium — severity is a first-class knob used to gate CI/CD via
	// --min-severity, and a silent downgrade could drop a real finding below
	// a severity gate with no error or log message.
	sev := finding.SeverityMedium
	if def.Severity != "" {
		parsed, ok := parseSeverity(def.Severity)
		if !ok {
			return nil, fmt.Errorf("custom rule %q: unrecognized severity %q (expected one of: critical, high, medium, low)", def.ID, def.Severity)
		}
		sev = parsed
	}

	return &CustomDetector{
		def:     def,
		pattern: pattern,
		sev:     sev,
	}, nil
}

// ID returns the unique identifier of the custom detector.
func (d *CustomDetector) ID() string { return d.def.ID }

// Description returns a human-readable description of the custom detector.
func (d *CustomDetector) Description() string { return d.def.Description }

// Keywords returns the Aho-Corasick pre-filter keywords for the custom detector.
func (d *CustomDetector) Keywords() []string { return d.def.Keywords }

// Severity returns the default severity level for the custom detector findings.
func (d *CustomDetector) Severity() finding.Severity { return d.sev }

// Scan searches the data for matches against the custom regex pattern.
// If an entropy threshold is defined, matches below it are skipped.
func (d *CustomDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := d.pattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		if d.def.Entropy > 0 && entropy.Calculate(match) < d.def.Entropy {
			continue
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

// RegisterCustomRules parses RuleDefs, creates detectors, and registers them.
// Returns the count of successfully registered rules and any errors.
//
// A rule whose ID collides with an already-registered detector (a built-in
// detector or a previously registered custom rule) is skipped with an error
// rather than registered, because detector.Register panics on duplicate IDs.
func RegisterCustomRules(rules []RuleDef) (int, []error) {
	var errs []error
	count := 0

	for _, def := range rules {
		det, err := NewFromDef(def)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// RegisterIfAbsent checks-and-inserts atomically, so a colliding ID is
		// rejected without the panic that detector.Register would raise.
		if !detector.RegisterIfAbsent(det) {
			errs = append(errs, fmt.Errorf("custom rule %q: ID already registered (built-in detector or duplicate custom rule)", det.ID()))
			continue
		}
		count++
	}

	return count, errs
}

// parseSeverity converts a rule's YAML severity string into a finding.Severity.
// The second return value is false when s is a non-empty string that does not
// match one of the four recognized (lowercase, exact) severity names; callers
// must treat that as an error rather than silently falling back to medium.
func parseSeverity(s string) (finding.Severity, bool) {
	switch s {
	case "critical":
		return finding.SeverityCritical, true
	case "high":
		return finding.SeverityHigh, true
	case "medium":
		return finding.SeverityMedium, true
	case "low":
		return finding.SeverityLow, true
	default:
		return finding.SeverityMedium, false
	}
}

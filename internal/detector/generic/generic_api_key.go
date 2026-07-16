// Package generic provides general-purpose secret detectors.
package generic

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/entropy"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// NOTE: the Apache APISIX-specific keywords/branches below are intentionally
// left bundled into this general-purpose detector rather than split into a
// dedicated `apisix` package (reviewed and accepted as-is; see review section
// 03-detectors-d2.md NIT "APISIX-keywords-in-generic"). Every other
// vendor-specific secret in the codebase gets its own package, so a future
// cleanup extracting `apisix` into its own detector would be consistent with
// that convention, but is not required by this change.
var apiKeyPattern = regexp.MustCompile(`(?i)(api[_\-]?key|api[_\-]?secret|secret[_\-]?key|x[_\-]?apisix[_\-]?key|apisix[_\-]?key|apisix[_\-]?admin[_\-]?key)[ \t]*[:=][ \t]*['"]?([a-zA-Z0-9/+=\-_]{16,64})['"]?`)

// APIKeyDetector detects generic API key assignments.
type APIKeyDetector struct{}

func (d *APIKeyDetector) ID() string { return "generic-api-key" }

func (d *APIKeyDetector) Description() string { return "Generic API Key" }
func (d *APIKeyDetector) Keywords() []string {
	return []string{
		"api_key", "api-key", "apikey",
		"api_secret", "api-secret", "apisecret",
		"secret_key", "secret-key", "secretkey",
		"apisix-key", "apisix_key", "x-apisix-key", "x_apisix_key", "apisix-admin-key",
	}
}
func (d *APIKeyDetector) Severity() finding.Severity { return finding.SeverityMedium }

// EntropyBased marks this as a heuristic detector: it matches arbitrary
// high-entropy strings rather than a fixed credential format, so it opts into
// the engine's Shannon-entropy floor (config entropy.threshold) in addition to
// its own baseline filter. Structural detectors do not implement this and are
// never entropy-gated.
func (d *APIKeyDetector) EntropyBased() bool { return true }

// minEntropy is the Shannon entropy floor a candidate value must clear to be
// considered plausibly random secret material rather than an ordinary
// identifier or human-readable placeholder. Raised from the original 3.0,
// which measurably let common non-secret identifiers through (e.g.
// "readonly_service_account" ~3.77, "CHANGE_THIS_VALUE_LATER1" ~3.74,
// dashless UUIDs ~3.25) — see review section 03-detectors-d2.md.
const minEntropy = 3.8

// minVowelRatioLetters is the minimum number of letter characters required
// before hasHighVowelRatio draws a conclusion; below this, the ratio is too
// noisy to be meaningful (e.g. a value that is mostly digits).
const minVowelRatioLetters = 8

// highVowelRatioThreshold is the vowel-to-letter ratio above which a value
// looks like natural-language text (English words, snake_case identifiers)
// rather than randomly-generated secret material. Randomly generated
// base64/hex/alphanumeric secrets rarely exceed ~30% vowels among their
// letter characters; English words/phrases typically sit at 35-45%.
const highVowelRatioThreshold = 0.35

// Scan searches the data for generic API key assignment patterns.
// Applies Shannon entropy filtering after regex matching; matches with
// entropy below minEntropy, or whose letter composition looks like
// natural-language text rather than random secret material, are skipped as
// unlikely to be real secrets.
func (d *APIKeyDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := apiKeyPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		value := match[2]

		// Skip low-entropy values — unlikely to be real secrets
		if entropy.Calculate(value) < minEntropy {
			continue
		}

		// Skip values whose letter composition reads as natural-language text
		// (env var names, human-readable placeholders) rather than random
		// secret material.
		if hasHighVowelRatio(value) {
			continue
		}

		// Skip placeholder/example values
		if isPlaceholder(value) {
			continue
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        value,
			Redacted:   detector.RedactBytes(value),
			ExtraData: map[string]string{
				"key_name": string(match[1]),
			},
		})
	}
	return findings
}

// placeholderPatterns are common dummy values used in example configs. Every
// entry MUST be lowercase: isPlaceholder compares against a lowercased copy
// of the candidate value, so a mixed-case entry here would never match
// (previously true for "TODO", "FIXME", "_API_KEY", "_SECRET_KEY", and
// "_API_SECRET" — see review section 03-detectors-d2.md).
var placeholderPatterns = [][]byte{
	[]byte("change_me"),
	[]byte("changeme"),
	[]byte("your_key_here"),
	[]byte("your-key-here"),
	[]byte("replace_me"),
	[]byte("xxxxxxxx"),
	[]byte("todo"),
	[]byte("fixme"),
	[]byte("placeholder"),
	[]byte("example"),
	[]byte("_api_key"),
	[]byte("_secret_key"),
	[]byte("_api_secret"),
}

func isPlaceholder(value []byte) bool {
	lower := bytes.ToLower(value)
	for _, p := range placeholderPatterns {
		if bytes.Contains(lower, p) {
			return true
		}
	}
	return false
}

// hasHighVowelRatio reports whether value's letter characters have a
// vowel-to-letter ratio consistent with natural-language text rather than
// randomly-generated secret material. See highVowelRatioThreshold.
func hasHighVowelRatio(value []byte) bool {
	letters := 0
	vowels := 0
	for _, b := range bytes.ToLower(value) {
		if b < 'a' || b > 'z' {
			continue
		}
		letters++
		switch b {
		case 'a', 'e', 'i', 'o', 'u':
			vowels++
		}
	}
	if letters < minVowelRatioLetters {
		return false
	}
	return float64(vowels)/float64(letters) >= highVowelRatioThreshold
}

func init() {
	detector.Register(&APIKeyDetector{})
}

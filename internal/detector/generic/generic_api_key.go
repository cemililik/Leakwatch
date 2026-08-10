// Package generic provides general-purpose secret detectors.
package generic

import (
	"bytes"
	"context"
	"regexp"
	"strings"

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
// apiKeyPattern accepts shell/YAML assignments and quoted object keys while
// capturing the opening and closing quotes separately. Scan validates that
// each quote pair matches and that the value ends at a real assignment
// boundary; keeping those checks in Go avoids unsupported regexp
// backreferences and prevents prefix matches on malformed or overlong values.
//
// Capture groups: key-open, key, key-close, value-open, value, value-close.
var apiKeyPattern = regexp.MustCompile(`(?i)(['"]?)(x[_\-]?apisix[_\-]?key|x[_\-]?api[_\-]?key|apisix[_\-]?admin[_\-]?key|apisix[_\-]?key|api[_\-]?key|api[_\-]?secret|secret[_\-]?key)(['"]?)[ \t\r\n]*[:=][ \t\r\n]*(['"]?)([a-zA-Z0-9/+=\-_]{16,64})(['"]?)`)

// APIKeyDetector detects generic API key assignments.
type APIKeyDetector struct{}

func (d *APIKeyDetector) ID() string { return "generic-api-key" }

func (d *APIKeyDetector) Description() string { return "Generic API Key" }
func (d *APIKeyDetector) Keywords() []string {
	return []string{
		"api_key", "api-key", "apikey",
		"api_secret", "api-secret", "apisecret",
		"secret_key", "secret-key", "secretkey",
		// The common "apisix" stem aligns every separator variation accepted by
		// the regexp (for example APISIX_ADMIN_KEY and APISIXADMINKEY) with the
		// matcher. Official X-API-KEY spellings are already covered by the
		// api-key/api_key/apikey substrings above.
		"apisix",
	}
}
func (d *APIKeyDetector) Severity() finding.Severity { return finding.SeverityMedium }

// EntropyBased marks this as a heuristic detector: it matches arbitrary
// high-entropy strings rather than a fixed credential format, so it opts into
// the engine's Shannon-entropy floor (config entropy.threshold) in addition to
// its own baseline filter. Structural detectors do not implement this and are
// never entropy-gated.
func (d *APIKeyDetector) EntropyBased() bool { return true }

// EntropyGated reports whether one raw finding should be subject to the
// engine-level entropy threshold. Explicit APISIX Admin API header names are a
// strong structural context and are therefore not entropy-gated; real APISIX
// keys are commonly 32-character hex values whose Shannon entropy can be below
// the generic threshold. Other generic assignments retain both entropy gates.
func (d *APIKeyDetector) EntropyGated(raw detector.RawFinding) bool {
	return !isAPISIXKeyName(raw.ExtraData["key_name"])
}

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
	matches := apiKeyPattern.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		keyOpen := submatchBytes(data, match, 1)
		key := submatchBytes(data, match, 2)
		keyClose := submatchBytes(data, match, 3)
		valueOpen := submatchBytes(data, match, 4)
		value := submatchBytes(data, match, 5)
		valueClose := submatchBytes(data, match, 6)
		if !validQuotePair(keyOpen, keyClose) || !validQuotePair(valueOpen, valueClose) {
			continue
		}
		if !hasAssignmentBoundary(data, match[1]) {
			continue
		}

		strongContext := isAPISIXKeyName(string(key))

		// Skip low-entropy values — unlikely to be real secrets
		if !strongContext && entropy.Calculate(value) < minEntropy {
			continue
		}

		// Skip values whose letter composition reads as natural-language text
		// (env var names, human-readable placeholders) rather than random
		// secret material.
		if !strongContext && hasHighVowelRatio(value) {
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
				"key_name": string(key),
			},
		})
	}
	return findings
}

func submatchBytes(data []byte, indexes []int, group int) []byte {
	start := indexes[group*2]
	end := indexes[group*2+1]
	return data[start:end]
}

func validQuotePair(open, close []byte) bool {
	if len(open) == 0 || len(close) == 0 {
		return len(open) == 0 && len(close) == 0
	}
	return len(open) == 1 && len(close) == 1 && open[0] == close[0]
}

// hasAssignmentBoundary rejects partial captures such as a 64-byte prefix of
// a longer value or the prefix before a disallowed character. Quoted values
// have already consumed their closing quote; both quoted and unquoted forms
// must then end at a configuration-token boundary.
func hasAssignmentBoundary(data []byte, end int) bool {
	if end >= len(data) {
		return true
	}
	switch data[end] {
	case ' ', '\t', '\r', '\n', ',', ';', '#', '}', ']':
		return true
	default:
		return false
	}
}

func isAPISIXKeyName(key string) bool {
	canonical := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(key))
	switch canonical {
	case "xapikey", "xapisixkey", "apisixkey", "apisixadminkey":
		return true
	default:
		return false
	}
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
	// Lowercase in the loop rather than allocating a copy via bytes.ToLower:
	// this runs on every candidate match, so the allocation is hot-path waste.
	for _, b := range value {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
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

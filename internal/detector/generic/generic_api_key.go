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
// capturing the character before the key and the closing key quote separately.
// This prevents an enclosing shell-string quote from being mistaken for a key
// quote while still validating JSON/TOML quoted keys. Scan also validates that
// the value ends at a real assignment
// boundary; keeping those checks in Go avoids unsupported regexp
// backreferences and prevents prefix matches on malformed or overlong values.
//
// Capture groups: key-prefix, key, key-close, value-open, value, value-close.
var apiKeyPattern = regexp.MustCompile(`(?i)(^|[^a-zA-Z0-9_])(x[_\-]?apisix[_\-]?key|x[_\-]?api[_\-]?key|apisix[_\-]?admin[_\-]?key|apisix[_\-]?key|api[_\-]?key|api[_\-]?secret|secret[_\-]?key)(['"]?)[ \t\r\n]*[:=][ \t\r\n]*(['"]?)([a-zA-Z0-9/+=\-_]{16,64})(['"]?)`)

var apiKeyNameReplacer = strings.NewReplacer("-", "", "_", "")

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
	return raw.ExtraData["key_context"] != "apisix"
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
	apisixPositions := asciiFoldPositions(data, []byte("apisix"))

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		keyPrefix := submatchBytes(data, match, 1)
		key := submatchBytes(data, match, 2)
		keyClosingQuote := submatchBytes(data, match, 3)
		valueOpen := submatchBytes(data, match, 4)
		value := submatchBytes(data, match, 5)
		valueClosingQuote := submatchBytes(data, match, 6)
		if !validKeyQuoteContext(keyPrefix, keyClosingQuote) ||
			!validValueQuoteContext(keyPrefix, keyClosingQuote, valueOpen, valueClosingQuote) {
			continue
		}
		if len(valueOpen) == 0 && len(valueClosingQuote) == 0 && !hasAssignmentBoundary(data, match[1]) {
			continue
		}

		// Reject cheap, deterministic false positives before provider-context and
		// entropy work. The package-level replacer and one APISIX position scan per
		// chunk keep the detector O(file size + matches).
		if isPlaceholder(value) || isDegenerateValue(value) || isBareReference(value) {
			continue
		}
		strongContext := hasStrongAPISIXContext(string(key), match[10], match[11], apisixPositions)

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

		extraData := map[string]string{"key_name": string(key)}
		if strongContext {
			extraData["key_context"] = "apisix"
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        value,
			Redacted:   detector.RedactBytes(value),
			ExtraData:  extraData,
			ByteStart:  match[10],
			ByteEnd:    match[11],
		})
	}
	return findings
}

func submatchBytes(data []byte, indexes []int, group int) []byte {
	start := indexes[group*2]
	end := indexes[group*2+1]
	return data[start:end]
}

func validQuotePair(open, closingQuote []byte) bool {
	if len(open) == 0 || len(closingQuote) == 0 {
		return len(open) == 0 && len(closingQuote) == 0
	}
	return len(open) == 1 && len(closingQuote) == 1 && open[0] == closingQuote[0]
}

func validKeyQuoteContext(prefix, closingQuote []byte) bool {
	if len(closingQuote) == 0 {
		return true
	}
	return len(prefix) == 1 && len(closingQuote) == 1 &&
		(prefix[0] == '\'' || prefix[0] == '"') && prefix[0] == closingQuote[0]
}

func validValueQuoteContext(prefix, keyClosingQuote, open, closingQuote []byte) bool {
	if validQuotePair(open, closingQuote) {
		return true
	}
	// In `curl -H "x-api-key: value"`, the surrounding shell quote appears
	// before the key and after the value. It is not a value quote pair.
	return len(keyClosingQuote) == 0 && len(open) == 0 && len(closingQuote) == 1 &&
		len(prefix) == 1 && prefix[0] == closingQuote[0] &&
		(prefix[0] == '\'' || prefix[0] == '"')
}

// hasAssignmentBoundary rejects partial captures such as a 64-byte prefix of
// a longer value or the prefix before a disallowed character. Quoted values
// have already consumed their closing quote; both quoted and unquoted forms
// must then end at a configuration-token boundary.
func hasAssignmentBoundary(data []byte, end int) bool {
	if end >= len(data) {
		return true
	}
	return !isAPIKeyValueContinuation(data[end])
}

func isAPIKeyValueContinuation(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || strings.ContainsRune("/+=-_.", rune(value))
}

func hasStrongAPISIXContext(key string, valueStart, valueEnd int, apisixPositions []int) bool {
	canonical := apiKeyNameReplacer.Replace(strings.ToLower(key))
	switch canonical {
	case "xapisixkey", "apisixkey", "apisixadminkey":
		return true
	case "xapikey":
		// Context must be independent of the candidate value itself. Otherwise a
		// generic X-API-KEY whose value happens to contain "apisix" could disable
		// its own false-positive gates.
		return apisixOutsideValue(apisixPositions, valueStart, valueEnd)
	default:
		return false
	}
}

func asciiFoldPositions(data, needle []byte) []int {
	var positions []int
	for i := 0; i+len(needle) <= len(data); i++ {
		if bytes.EqualFold(data[i:i+len(needle)], needle) {
			positions = append(positions, i)
		}
	}
	return positions
}

func apisixOutsideValue(positions []int, valueStart, valueEnd int) bool {
	if len(positions) == 0 {
		return false
	}
	return positions[0]+len("apisix") <= valueStart || positions[len(positions)-1] >= valueEnd
}

func isDegenerateValue(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, b := range value[1:] {
		if b != value[0] {
			return false
		}
	}
	return true
}

// isBareReference rejects identifier-like indirections such as
// APISIX_ADMIN_KEY. Braced environment/secret-manager references are already
// outside the candidate character class; this covers the common unbraced form
// without suppressing mixed-case or punctuation-rich real credentials.
func isBareReference(value []byte) bool {
	hasSeparator := false
	hasLetter := false
	for _, b := range value {
		switch {
		case b >= 'A' && b <= 'Z':
			hasLetter = true
		case b >= '0' && b <= '9':
		case b == '_':
			hasSeparator = true
		default:
			return false
		}
	}
	return hasLetter && hasSeparator
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

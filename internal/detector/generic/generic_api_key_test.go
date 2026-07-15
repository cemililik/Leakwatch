package generic

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyDetector_Metadata(t *testing.T) {
	d := &APIKeyDetector{}
	assert.Equal(t, "generic-api-key", d.ID())
	assert.Equal(t, "Generic API Key", d.Description())
	assert.Equal(t, finding.SeverityMedium, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestAPIKeyDetector_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "api_key with equals",
			input:    `api_key = "abcdef1234567890abcdef1234567890"`,
			expected: 1,
		},
		{
			name:     "API_KEY with equals",
			input:    `API_KEY = "abcdef1234567890abcdef1234567890"`,
			expected: 1,
		},
		{
			name:     "api-key with colon",
			input:    `api-key: abcdef1234567890abcdef1234567890`,
			expected: 1,
		},
		{
			name:     "secret_key with equals",
			input:    `secret_key = "abcdef1234567890abcdef1234567890"`,
			expected: 1,
		},
		{
			name:     "api_secret with colon",
			input:    `api_secret: abcdef1234567890abcdef1234567890`,
			expected: 1,
		},
		{
			name:     "value too short",
			input:    `api_key = "short"`,
			expected: 0,
		},
		{
			name:     "no assignment pattern",
			input:    "just some api_key mention in text",
			expected: 0,
		},
		{
			name:     "plain text",
			input:    "no secrets here",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name:     "multiple keys",
			input:    "api_key = \"abcdef1234567890abcdef1234567890\"\nsecret_key = \"1234567890abcdef1234567890abcdef\"",
			expected: 2,
		},
		{
			name:     "base64 value",
			input:    `api_key = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciBsZWFrd2F0Y2g="`,
			expected: 1,
		},
	}

	d := &APIKeyDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
		})
	}
}

func TestAPIKeyDetector_Scan_RedactsValue(t *testing.T) {
	d := &APIKeyDetector{}
	input := `api_key = "abcdef1234567890abcdef1234567890"`

	findings := d.Scan(context.Background(), []byte(input))
	require.Len(t, findings, 1)

	assert.Equal(t, "****7890", findings[0].Redacted)
	assert.Equal(t, "api_key", findings[0].ExtraData["key_name"])
}

func TestAPIKeyDetector_Scan_LowEntropy_SkipsMatch(t *testing.T) {
	d := &APIKeyDetector{}
	// Low entropy value: repeating character sequence
	input := `api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`

	findings := d.Scan(context.Background(), []byte(input))
	assert.Empty(t, findings, "low entropy value should be skipped")
}

// TestAPIKeyDetector_Scan_CapturesFullBase64Value regression-tests the value
// character class: it must include "+" and "=" so a base64-encoded secret
// (including its trailing "=" padding) is captured in full rather than
// silently truncated. See review section 03-detectors-d2.md MED finding
// "generic_api_key.go:14".
func TestAPIKeyDetector_Scan_CapturesFullBase64Value(t *testing.T) {
	// 44-char base64 with trailing "=" padding and a "+" in the body.
	value := "dGhpcyBpcyBhIHRlc3Qga2V5+Zm9yIGxlYWt3YXRjaA="
	input := `api_key = "` + value + `"`

	d := &APIKeyDetector{}
	findings := d.Scan(context.Background(), []byte(input))

	require.Len(t, findings, 1)
	assert.Equal(t, value, string(findings[0].Raw), "captured value must include trailing '=' and embedded '+'")
}

// TestAPIKeyDetector_Scan_NonSecretIdentifiers_NotFlagged regression-tests
// the false-positive-suppression pipeline (entropy floor + vowel-ratio
// heuristic + placeholder filtering) against realistic non-secret
// identifier-like strings that previously cleared the old 3.0 entropy floor.
// See review section 03-detectors-d2.md HIGH finding "generic_api_key.go:49".
func TestAPIKeyDetector_Scan_NonSecretIdentifiers_NotFlagged(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "snake_case phrase", value: "development_environment"},
		{name: "another snake_case phrase", value: "my_local_test_key_value"},
		{name: "screaming snake with digit", value: "CHANGE_THIS_VALUE_LATER1"},
		{name: "readonly identifier", value: "readonly_service_account"},
		{name: "dashless UUID", value: "550e8400e29b41d4a716446655440000"},
	}

	d := &APIKeyDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `api_key = "` + tt.value + `"`
			findings := d.Scan(context.Background(), []byte(input))
			assert.Empty(t, findings, "non-secret identifier %q should not be flagged", tt.value)
		})
	}
}

// TestAPIKeyDetector_Scan_SkipsHighVowelRatio_ThroughFullPipeline regression-
// tests that the hasHighVowelRatio skip path inside Scan is reachable: the
// value below clears the entropy floor and contains no known placeholder
// substring, so it must be the vowel-ratio heuristic itself that suppresses
// the finding.
func TestAPIKeyDetector_Scan_SkipsHighVowelRatio_ThroughFullPipeline(t *testing.T) {
	value := "AuthenticationSessionId2024"
	require.False(t, isPlaceholder([]byte(value)), "fixture must not be a known placeholder to isolate the vowel-ratio branch")
	require.True(t, hasHighVowelRatio([]byte(value)), "fixture must actually trip the vowel-ratio heuristic for this test to be meaningful")

	input := `api_key = "` + value + `"`

	d := &APIKeyDetector{}
	findings := d.Scan(context.Background(), []byte(input))
	assert.Empty(t, findings, "natural-language-looking value must be skipped by the vowel-ratio heuristic")
}

// TestAPIKeyDetector_Scan_SkipsPlaceholder_ThroughFullPipeline regression-tests
// that the isPlaceholder skip path inside Scan is actually reachable: the
// value below clears both the entropy floor and the vowel-ratio heuristic, so
// it must be isPlaceholder itself that suppresses the finding. See review
// section 19-test-quality.md MED finding "generic_api_key.go:87".
func TestAPIKeyDetector_Scan_SkipsPlaceholder_ThroughFullPipeline(t *testing.T) {
	value := "X_API_SECRET_9f8e7d6c5b4a3f2e1d0c9b"
	require.GreaterOrEqual(t, len(value), 16)
	require.False(t, hasHighVowelRatio([]byte(value)), "fixture must bypass the vowel-ratio heuristic to isolate isPlaceholder")
	require.True(t, isPlaceholder([]byte(value)), "fixture must actually be a placeholder for this test to be meaningful")

	input := `api_key = "` + value + `"`

	d := &APIKeyDetector{}
	findings := d.Scan(context.Background(), []byte(input))
	assert.Empty(t, findings, "placeholder value must be skipped even though it clears entropy and vowel-ratio checks")
}

// TestIsPlaceholder_AllPatterns_MixedCase directly tests isPlaceholder against
// every entry in placeholderPatterns using mixed-case input, regression-testing
// the case bug where 5 of 13 patterns ("TODO", "FIXME", "_API_KEY",
// "_SECRET_KEY", "_API_SECRET") were declared in uppercase and could never
// match the lowercased candidate. See review section 03-detectors-d2.md HIGH
// finding "generic_api_key.go:87".
func TestIsPlaceholder_AllPatterns_MixedCase(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "change_me lowercase", value: "please_change_me_now"},
		{name: "CHANGE_ME uppercase", value: "PLEASE_CHANGE_ME_NOW"},
		{name: "changeme lowercase", value: "changeme123456789"},
		{name: "CHANGEME uppercase", value: "CHANGEME123456789"},
		{name: "your_key_here", value: "your_key_here_1234567890"},
		{name: "YOUR_KEY_HERE uppercase", value: "YOUR_KEY_HERE_1234567890"},
		{name: "your-key-here", value: "your-key-here-1234567890"},
		{name: "replace_me", value: "replace_me_1234567890ab"},
		{name: "REPLACE_ME uppercase", value: "REPLACE_ME_1234567890AB"},
		{name: "xxxxxxxx", value: "xxxxxxxx1234567890abcd"},
		{name: "TODO uppercase", value: "TODO_fill_in_1234567890"},
		{name: "todo lowercase", value: "todo_fill_in_1234567890"},
		{name: "Todo mixed case", value: "Todo_fill_in_1234567890"},
		{name: "FIXME uppercase", value: "FIXME_this_1234567890ab"},
		{name: "fixme lowercase", value: "fixme_this_1234567890ab"},
		{name: "placeholder", value: "placeholder1234567890AB"},
		{name: "PLACEHOLDER uppercase", value: "PLACEHOLDER1234567890AB"},
		{name: "example", value: "example1234567890ABCDEF"},
		{name: "EXAMPLE uppercase", value: "EXAMPLE1234567890ABCDEF"},
		{name: "_API_KEY uppercase suffix", value: "MY_APP_API_KEY_12345678"},
		{name: "_api_key lowercase suffix", value: "my_app_api_key_12345678"},
		{name: "_SECRET_KEY uppercase suffix", value: "MY_APP_SECRET_KEY_12345"},
		{name: "_secret_key lowercase suffix", value: "my_app_secret_key_12345"},
		{name: "_API_SECRET uppercase suffix", value: "MY_APP_API_SECRET_12345"},
		{name: "_api_secret lowercase suffix", value: "my_app_api_secret_12345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, isPlaceholder([]byte(tt.value)), "expected %q to be recognized as a placeholder", tt.value)
		})
	}
}

// TestIsPlaceholder_NonPlaceholder_ReturnsFalse ensures isPlaceholder does not
// over-match: a random-looking secret containing none of the known dummy
// substrings must not be treated as a placeholder.
func TestIsPlaceholder_NonPlaceholder_ReturnsFalse(t *testing.T) {
	assert.False(t, isPlaceholder([]byte("aB3kL9mN2pQ7rT4sU6vW8xY0zA1bC2d")))
}

// TestHasHighVowelRatio_TooFewLetters_ReturnsFalse ensures the ratio isn't
// computed off too small a letter sample (e.g. a mostly-numeric value), where
// a couple of vowels could otherwise produce a misleadingly high ratio.
func TestHasHighVowelRatio_TooFewLetters_ReturnsFalse(t *testing.T) {
	assert.False(t, hasHighVowelRatio([]byte("12345678aei")), "fewer than minVowelRatioLetters letters must not trip the heuristic")
}

// TestHasHighVowelRatio_RandomSecret_ReturnsFalse ensures a plausible random
// secret (low vowel density) is not misclassified as natural-language text.
func TestHasHighVowelRatio_RandomSecret_ReturnsFalse(t *testing.T) {
	assert.False(t, hasHighVowelRatio([]byte("aB3kL9mN2pQ7rT4sU6vW8xY0zA1bC2d")))
}

// TestAPIKeyDetector_ScanViaMatcher_KeywordRegexAlignment is a
// testutil.ScanViaMatcher regression test proving the detector's Keywords()
// actually let the Aho-Corasick matcher gate select it at runtime for a
// realistic positive match, mirroring the telegram DETB-M-01 precedent. See
// review sections 02-detectors-d1.md and 19-test-quality.md ("no A-D detector
// uses testutil.ScanViaMatcher").
func TestAPIKeyDetector_ScanViaMatcher_KeywordRegexAlignment(t *testing.T) {
	input := `api_key = "aB3kL9mN2pQ7rT4sU6vW8xY0zA1bC2d"`

	d := &APIKeyDetector{}
	findings := testutil.ScanViaMatcher(d, []byte(input))

	require.Len(t, findings, 1, "realistic api_key assignment must survive the matcher gate")
	assert.Equal(t, "generic-api-key", findings[0].DetectorID)
}

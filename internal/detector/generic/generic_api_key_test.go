package generic

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/HodeTech/leakwatch/internal/source"
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
		{
			name:     "SDK constructor quoted value",
			input:    `client = OpenAI(api_key="Q7mN2pL9rT4vW8xYzC6bH3kF")`,
			expected: 1,
		},
		{
			name:     "URL query unquoted value",
			input:    `https://api.example.test/?api_key=Q7mN2pL9rT4vW8xYzC6bH3kF&next=1`,
			expected: 1,
		},
		{
			name:     "curl double quoted header",
			input:    `curl -H "x-api-key: Q7mN2pL9rT4vW8xYzC6bH3kF" https://api.example.test`,
			expected: 1,
		},
		{
			name:     "curl single quoted header",
			input:    `curl -H 'X-API-Key: Q7mN2pL9rT4vW8xYzC6bH3kF' https://api.example.test`,
			expected: 1,
		},
		{
			name:     "embedded shell command",
			input:    `run: "curl -H \"x-api-key: Q7mN2pL9rT4vW8xYzC6bH3kF\" https://api.example.test"`,
			expected: 1,
		},
		{
			name:     "XML attribute quoted value",
			input:    `<cfg apiKey="Q7mN2pL9rT4vW8xYzC6bH3kF"/>`,
			expected: 1,
		},
		{
			name:     "double quoted JSON key",
			input:    `{"X-APISIX-KEY": "Q7mN2pL9rT4vW8xY0zA1bC3dE5fG6hJ8kM2nP4sR7tV"}`,
			expected: 1,
		},
		{
			name:     "single quoted object key",
			input:    `{'x-apisix-key' : 'Q7mN2pL9rT4vW8xY0zA1bC3dE5fG6hJ8kM2nP4sR7tV'}`,
			expected: 1,
		},
		{
			name:     "official APISIX header with independent context and low entropy hex value",
			input:    `{"Gateway": "Apache APISIX", "X-API-KEY": "01234567012345670123456701234567"}`,
			expected: 1,
		},
		{
			name:     "generic X-API-KEY without APISIX context retains entropy filters",
			input:    `{"X-API-KEY": "01234567012345670123456701234567"}`,
			expected: 0,
		},
		{
			name:     "generic X-API-KEY natural language value is not structural",
			input:    `{"X-API-KEY": "development_environment"}`,
			expected: 0,
		},
		{
			name:     "multiline JSON whitespace",
			input:    "{\r\n  \"Gateway\": \"APISIX\",\r\n  \"X-API-KEY\"\r\n  :\r\n  \"01234567012345670123456701234567\"\r\n}",
			expected: 1,
		},
		{
			name:     "sensitive header list entry is not an assignment",
			input:    `{"SensitiveHeaders": ["Authorization", "X-APISIX-KEY"]}`,
			expected: 0,
		},
		{
			name:     "mismatched key quotes",
			input:    `{"X-APISIX-KEY': "Q7mN2pL9rT4vW8xY0zA1bC3dE5fG6hJ8kM2nP4sR7tV"}`,
			expected: 0,
		},
		{
			name:     "mismatched value quotes",
			input:    `{"X-APISIX-KEY": "Q7mN2pL9rT4vW8xY0zA1bC3dE5fG6hJ8kM2nP4sR7tV'}`,
			expected: 0,
		},
		{
			name:     "unterminated quoted value",
			input:    `{"X-APISIX-KEY": "Q7mN2pL9rT4vW8xY0zA1bC3dE5fG6hJ8kM2nP4sR7tV}`,
			expected: 0,
		},
		{
			name:     "disallowed value suffix",
			input:    `{"X-APISIX-KEY": "Q7mN2pL9rT4vW8xY.invalid"}`,
			expected: 0,
		},
		{
			name:     "unquoted disallowed value suffix",
			input:    `X-APISIX-KEY = Q7mN2pL9rT4vW8xY.invalid`,
			expected: 0,
		},
		{
			name:     "overlong allowed value is rejected not truncated",
			input:    `{"X-APISIX-KEY": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"}`,
			expected: 0,
		},
		{
			name:     "degenerate explicit APISIX value",
			input:    `{"X-APISIX-KEY": "0000000000000000"}`,
			expected: 0,
		},
		{
			name:     "bare environment reference in explicit APISIX field",
			input:    `{"X-APISIX-KEY": "APISIX_ADMIN_KEY"}`,
			expected: 0,
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

type fixtureSource struct {
	data []byte
}

func (s *fixtureSource) Type() string                   { return "fixture" }
func (s *fixtureSource) Validate(context.Context) error { return nil }
func (s *fixtureSource) Err() error                     { return nil }
func (s *fixtureSource) Chunks(_ context.Context) <-chan source.Chunk {
	chunks := make(chan source.Chunk, 1)
	chunks <- source.Chunk{
		Data: s.data,
		SourceMetadata: finding.SourceMetadata{
			SourceType: "filesystem",
			FilePath:   "appsettings.synthetic.json",
		},
	}
	close(chunks)
	return chunks
}

func readSyntheticAppsettings(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "appsettings.synthetic.json"))
	require.NoError(t, err)
	return data
}

func TestAPIKeyDetector_AppsettingsJSON_DirectAndMatcherParity(t *testing.T) {
	data := readSyntheticAppsettings(t)
	d := &APIKeyDetector{}

	direct := d.Scan(context.Background(), data)
	viaMatcher := testutil.ScanViaMatcher(d, data)

	require.Len(t, direct, 3, "the three APISIX assignments must be detected")
	require.Equal(t, direct, viaMatcher, "quoted JSON assignments must survive the production matcher gate")
	for _, got := range direct {
		assert.Equal(t, "X-APISIX-KEY", got.ExtraData["key_name"])
		assert.NotEqual(t, string(got.Raw), got.Redacted)
	}
}

func TestAPIKeyDetector_APISIXSpellings_IsolatedMatcherParity(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "official header hyphen", key: "X-API-KEY"},
		{name: "official header underscore", key: "X_API_KEY"},
		{name: "local header", key: "X-APISIX-KEY"},
		{name: "admin key underscore", key: "APISIX_ADMIN_KEY"},
		{name: "admin key compact", key: "APISIXADMINKEY"},
		{name: "apisix key mixed separators", key: "APISIX-KEY"},
	}

	d := &APIKeyDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(`{"Gateway": "Apache APISIX", "` + tt.key + `": "01234567012345670123456701234567"}`)
			direct := d.Scan(context.Background(), input)
			viaMatcher := testutil.ScanViaMatcher(d, input)
			require.Len(t, direct, 1)
			require.Equal(t, direct, viaMatcher, "each accepted spelling must independently select the detector")
			assert.Equal(t, tt.key, direct[0].ExtraData["key_name"])
			assert.Equal(t, "apisix", direct[0].ExtraData["key_context"])
			assert.False(t, d.EntropyGated(direct[0]), "explicit APISIX context must bypass entropy gating")
			assert.Equal(t, string(direct[0].Raw), string(input[direct[0].ByteStart:direct[0].ByteEnd]))
		})
	}
}

func TestAPIKeyDetector_XAPIKey_ValueCannotProvideItsOwnAPISIXContext(t *testing.T) {
	data := []byte(`{"X-API-KEY": "aB3kAPISIX9mN2pQ7rT4vW8xY0zC5dF"}`)
	d := &APIKeyDetector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1, "high-entropy generic header remains detectable")
	assert.Empty(t, findings[0].ExtraData["key_context"])
	assert.True(t, d.EntropyGated(findings[0]), "candidate bytes must not establish their own structural context")
}

func TestAPIKeyDetector_AppsettingsJSON_FullEngine(t *testing.T) {
	data := readSyntheticAppsettings(t)
	d := &APIKeyDetector{}
	eng := engine.New(engine.Config{
		Concurrency:      1,
		Detectors:        []detector.Detector{d},
		EnableEntropy:    true,
		EntropyThreshold: 4.0,
		Clock: func() time.Time {
			return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		},
	})

	result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
	require.NoError(t, err)
	require.Len(t, result.Findings, 3, "all APISIX assignments must survive matcher, detector, and entropy gates")

	lines := make([]int, 0, len(result.Findings))
	for _, got := range result.Findings {
		assert.Equal(t, "generic-api-key", got.DetectorID)
		assert.Empty(t, got.Raw, "raw values must not be exposed by the default engine result")
		lines = append(lines, got.SourceMetadata.Line)
	}
	assert.Equal(t, linesContaining(data, []byte(`"X-APISIX-KEY":`)), lines)
}

func TestAPIKeyDetector_APISIXLowEntropy_SurvivesFullEngine(t *testing.T) {
	data := []byte("{\n  \"Gateway\": \"Apache APISIX\",\n  \"X-API-KEY\": \"01234567012345670123456701234567\"\n}\n")
	d := &APIKeyDetector{}
	eng := engine.New(engine.Config{
		Concurrency:      1,
		Detectors:        []detector.Detector{d},
		EnableEntropy:    true,
		EntropyThreshold: 4.0,
	})

	result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "strong APISIX context must survive the generic entropy thresholds")
	assert.Less(t, result.Findings[0].Entropy, 3.8, "fixture must prove the low-entropy structural path")
	assert.Equal(t, 3, result.Findings[0].SourceMetadata.Line)
}

func TestAPIKeyDetector_ExactSpan_PreventsDecoyLineAndIgnore(t *testing.T) {
	value := "01234567012345670123456701234567"
	data := []byte("{\n" +
		`  "DocumentationExample": "` + value + `", // leakwatch:ignore:generic-api-key` + "\n" +
		`  "X-APISIX-KEY": "` + value + `"` + "\n}\n")
	d := &APIKeyDetector{}
	eng := engine.New(engine.Config{
		Concurrency:      1,
		Detectors:        []detector.Detector{d},
		EnableEntropy:    true,
		EntropyThreshold: 4.0,
	})

	result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "an ignored same-value decoy must not suppress the actual assignment")
	assert.Equal(t, 3, result.Findings[0].SourceMetadata.Line)
}

func linesContaining(data, marker []byte) []int {
	var lines []int
	for i, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.Contains(line, marker) {
			lines = append(lines, i+1)
		}
	}
	return lines
}

func TestAPIKeyDetector_EntropyBased(t *testing.T) {
	// The generic detector is heuristic (matches arbitrary high-entropy
	// strings), so it must opt into the engine's entropy floor.
	assert.True(t, (&APIKeyDetector{}).EntropyBased(),
		"generic-api-key must be entropy-based so the engine gates it on entropy")

	d := &APIKeyDetector{}
	heuristic := detector.RawFinding{ExtraData: map[string]string{"key_name": "api_key"}}
	assert.True(t, d.EntropyGated(heuristic), "ordinary generic assignments must retain engine entropy gating")
}

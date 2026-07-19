package detector

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
)

func TestRedact_LongValue_RevealsOnlyLastFour(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "typical secret reveals last four",
			value: "AKIAIOSFODNN7EXAMPLE",
			want:  "****MPLE",
		},
		{
			name:  "value with provider prefix hides leading body",
			value: "sk-ant-Abc1234567890XYZ",
			want:  "****0XYZ",
		},
		{
			name:  "exactly five characters reveals last four",
			value: "abcde",
			want:  "****bcde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.value)
			assert.Equal(t, tt.want, got)
			// The first body character must never appear at the front of the
			// redacted output.
			assert.True(t, strings.HasPrefix(got, redactMask))
			assert.NotContains(t, got, tt.value[:1]+tt.value[1:len(tt.value)-revealedSuffixLen])
		})
	}
}

func TestRedact_ShortValue_FullyMasked(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "one char", value: "a"},
		{name: "exactly suffix length", value: "abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, redactMask, Redact(tt.value))
		})
	}
}

func TestRedactBytes_MatchesRedact(t *testing.T) {
	values := []string{"", "abc", "abcd", "abcde", "AKIAIOSFODNN7EXAMPLE"}
	for _, v := range values {
		assert.Equal(t, Redact(v), RedactBytes([]byte(v)))
	}
}

func TestRedact_UnicodeValue_RevealsLastFourRunesAsValidUTF8(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			// Multi-byte runes occupy the trailing revealedSuffixLen runes; a
			// byte-based slice here would split a rune and produce invalid UTF-8.
			name:  "multi-byte runes at the end",
			value: "secret-token-🔑🔒💻🚀",
			want:  "****🔑🔒💻🚀",
		},
		{
			name:  "multi-byte runes throughout, short value fully masked",
			value: "🔑🔒",
			want:  redactMask,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.value)
			assert.Equal(t, tt.want, got)
			assert.True(t, utf8.ValidString(got), "redacted output must be valid UTF-8")
		})
	}
}

func TestRedactBytes_UnicodeValue_MatchesRedact(t *testing.T) {
	value := "secret-token-🔑🔒💻🚀"
	assert.Equal(t, Redact(value), RedactBytes([]byte(value)))
}

func TestRedactURLPassword_VariousFormats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard user:pass@host",
			input:    "amqp://user:password@host:5672/",
			expected: "amqp://user:****@host:5672/",
		},
		{
			name:     "user without password",
			input:    "redis://user@host:6379/0",
			expected: "redis://user:****@host:6379/0",
		},
		{
			// No userinfo at all: fail safe and mask everything but the scheme.
			name:     "no credentials in URL",
			input:    "amqp://host:5672/",
			expected: "amqp://****",
		},
		{
			// A credential-shaped substring inside the path/query with no
			// authority userinfo must never be echoed back verbatim.
			name:     "embedded credential in path is masked, not leaked",
			input:    "amqp://simplehost/path?redirect=http://user:s3cr3tP4ss@evil.com",
			expected: "amqp://****",
		},
		{
			name:     "unparseable input is fully masked",
			input:    "amqp://user:pass@\x7f",
			expected: "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactURLPassword(tt.input)
			assert.Equal(t, tt.expected, got)
			assert.NotEqual(t, tt.input, got)
		})
	}
}

func TestHasAnyKeyword_CaseInsensitiveMatch(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		keywords []string
		want     bool
	}{
		{
			name:     "exact case match",
			data:     "the notion API token is set",
			keywords: []string{"notion"},
			want:     true,
		},
		{
			name:     "differing case still matches",
			data:     "NOTION_TOKEN=abc123",
			keywords: []string{"notion"},
			want:     true,
		},
		{
			name:     "mixed case keyword against mixed case data",
			data:     "Using Notion for docs",
			keywords: []string{"NOTION"},
			want:     true,
		},
		{
			name:     "no keyword present",
			data:     "just some unrelated text",
			keywords: []string{"notion", "okta"},
			want:     false,
		},
		{
			name:     "empty data",
			data:     "",
			keywords: []string{"notion"},
			want:     false,
		},
		{
			name:     "empty keywords",
			data:     "notion",
			keywords: nil,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasAnyKeyword([]byte(tt.data), tt.keywords...)
			assert.Equal(t, tt.want, got)
		})
	}
}

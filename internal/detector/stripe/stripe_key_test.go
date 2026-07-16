package stripe

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLiveKey_Metadata(t *testing.T) {
	d := &LiveKey{}
	assert.Equal(t, "stripe-api-key-live", d.ID())
	assert.Equal(t, "Stripe Live API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestTestKey_Metadata(t *testing.T) {
	d := &TestKey{}
	assert.Equal(t, "stripe-api-key-test", d.ID())
	assert.Equal(t, "Stripe Test API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestLiveKey_Scan_MatchesValidKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid sk_live key",
			input:    "sk_live_AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "sk_live_****UvWx",
		},
		{
			name:     "valid rk_live key",
			input:    "rk_live_AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "rk_live_****UvWx",
		},
		{
			name:     "key in env var",
			input:    `STRIPE_SECRET_KEY=sk_live_AbCdEfGhIjKlMnOpQrStUvWx`,
			expected: 1,
		},
		{
			name:     "key in JSON",
			input:    `{"api_key": "sk_live_AbCdEfGhIjKlMnOpQrStUvWx"}`,
			expected: 1,
		},
		{
			name:     "key in large text",
			input:    strings.Repeat("x", 10000) + "sk_live_AbCdEfGhIjKlMnOpQrStUvWx" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &LiveKey{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

func TestLiveKey_Scan_DoesNotMatchTestKeys(t *testing.T) {
	d := &LiveKey{}
	findings := d.Scan(context.Background(), []byte("sk_test_AbCdEfGhIjKlMnOpQrStUvWx"))
	assert.Empty(t, findings)
}

func TestTestKey_Scan_MatchesValidKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid sk_test key",
			input:    "sk_test_AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "sk_test_****UvWx",
		},
		{
			name:     "valid rk_test key",
			input:    "rk_test_AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "rk_test_****UvWx",
		},
		{
			name:     "multiple test keys",
			input:    "sk_test_AbCdEfGhIjKlMnOpQrStUvWx rk_test_AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 2,
		},
	}

	d := &TestKey{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

func TestTestKey_Scan_DoesNotMatchLiveKeys(t *testing.T) {
	d := &TestKey{}
	findings := d.Scan(context.Background(), []byte("sk_live_AbCdEfGhIjKlMnOpQrStUvWx"))
	assert.Empty(t, findings)
}

// TestRedactStripeKey_DefensiveFallbacks exercises redactStripeKey's
// fallback-to-full-mask branches directly. In practice redactStripeKey is
// only ever called with a string that already matched liveKeyPattern or
// testKeyPattern (which guarantees a well-formed "sk_live_..."/"rk_test_..."
// shape), so these malformed shapes cannot reach it via Scan. Testing the
// function directly documents and locks in its fail-safe behavior should it
// ever be reused with untrusted input.
func TestRedactStripeKey_DefensiveFallbacks(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no underscore at all",
			input:    "abcdefgh",
			expected: "****",
		},
		{
			name:     "underscore is the last character",
			input:    "a_",
			expected: "****",
		},
		{
			name:     "only one underscore, no second underscore",
			input:    "sk_liveonly",
			expected: "****",
		},
		{
			name:     "second underscore is the final character",
			input:    "sk_live_",
			expected: "****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, redactStripeKey(tt.input))
		})
	}
}

func TestKey_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short key value",
			input: "sk_live_short",
		},
		{
			name:  "wrong prefix",
			input: "pk_live_AbCdEfGhIjKlMnOpQrStUvWx",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	liveD := &LiveKey{}
	testD := &TestKey{}
	for _, tt := range tests {
		t.Run(tt.name+"_live", func(t *testing.T) {
			findings := liveD.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
		t.Run(tt.name+"_test", func(t *testing.T) {
			findings := testD.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

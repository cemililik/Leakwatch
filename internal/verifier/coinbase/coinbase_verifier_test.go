package coinbase

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_ValidFormatKey_ReturnsUnverifiedFormatValid(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678"),
		Redacted:   "****5678",
	}

	result := v.Verify(context.Background(), raw)

	// A legacy Coinbase key cannot be verified live without HMAC signing and the
	// paired secret, so the verifier must never claim active/inactive.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Contains(t, result.Message, "live verification not supported")
}

func TestVerify_InvalidFormatKey_ReturnsUnverifiedFormatInvalid(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		// Too short and contains an out-of-charset character.
		Raw:      []byte("short key!"),
		Redacted: "****key!",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_NeverReturnsActiveOrInactive(t *testing.T) {
	v := &Verifier{}

	inputs := []string{
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678",
		strings.Repeat("a", 64),
		"not a key",
		"",
	}

	for _, in := range inputs {
		result := v.Verify(context.Background(), detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte(in),
		})
		assert.Equal(t, finding.StatusUnverified, result.Status,
			"format-only verifier must never claim a live active/inactive result")
	}
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "coinbase-api-key", v.Type())
}

func TestVerify_EmptyToken_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty token", result.Message)
}

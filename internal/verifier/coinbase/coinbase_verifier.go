// Package coinbase provides a verifier for legacy Coinbase API keys.
//
// A legacy Coinbase API key is one half of a key/secret pair, and Coinbase's v2
// API authenticates it with timestamp-based HMAC-SHA256 request signing
// (CB-ACCESS-KEY / CB-ACCESS-SIGN / CB-ACCESS-TIMESTAMP headers), NOT a bearer
// token. Correct live verification would require BOTH the key and its paired
// secret to compute the signature, but the detector captures the key and the
// secret as independent findings with no pairing, so the signing inputs are not
// reliably available here. Rather than send an unauthenticated call that cannot
// succeed (and would misreport every real key as invalid), this verifier is a
// format-only (Tier 3) check: it validates the key shape and always returns
// StatusUnverified, never claiming a live active/inactive result.
// It NEVER logs or persists raw key values.
package coinbase

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "coinbase-api-key"

// coinbaseKeyFormat matches the character set and length range the detector
// emits for a legacy Coinbase API key/secret value.
var coinbaseKeyFormat = regexp.MustCompile(`^[A-Za-z0-9+/=]{16,64}$`)

// Verifier performs a format-only check on a legacy Coinbase API key. It never
// makes a network call and never logs or persists raw key values.
type Verifier struct{}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify performs a format-only validation of the detected Coinbase API key.
// Live verification is intentionally not attempted (see the package doc): the
// legacy API requires HMAC-SHA256 signing with the paired secret, which is not
// reliably available. The result is therefore always StatusUnverified.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	if !coinbaseKeyFormat.MatchString(token) {
		slog.DebugContext(ctx, "coinbase verifier: key does not match expected format")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid; live verification not supported (legacy API requires HMAC signing with paired secret)",
		}
	}

	slog.DebugContext(ctx, "coinbase verifier: key format is valid")
	return finding.VerificationResult{
		Status:  finding.StatusUnverified,
		Message: "format valid; live verification not supported (legacy API requires HMAC signing with paired secret)",
	}
}

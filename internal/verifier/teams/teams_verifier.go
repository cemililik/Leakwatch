// Package teams provides a verifier for Microsoft Teams webhook URLs.
//
// Security note: a Teams incoming webhook is a write-only endpoint — the only
// way to interact with it is to POST a message, which would deliver a visible
// card to a (possibly customer-owned) channel. Delivering a message during a
// scan is a destructive side effect and violates the project's secret-safety
// rules. Therefore this verifier performs a NON-DESTRUCTIVE probe: it POSTs a
// deliberately empty JSON object ("{}"), which Teams rejects as a bad payload
// (HTTP 400) WITHOUT rendering a card. That 400 distinguishes a real, active
// webhook from a deleted/disabled one (HTTP 404) or an invalid host
// (connection error). Ambiguous responses (for example a 2xx, which a genuine
// Teams webhook never returns for an empty payload) fall back to Unverified
// rather than risk a false positive.
package teams

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "teams-webhook"

// Verifier checks whether a Microsoft Teams webhook URL is active by sending
// a non-destructive probe. It NEVER logs or persists raw webhook URLs and it
// NEVER delivers a visible message to the target channel.
type Verifier struct {
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

var _ verifier.RequestGatedVerifier = (*Verifier)(nil)

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify probes the detected Teams webhook URL without delivering a message.
//
// It POSTs an empty JSON object so that a real webhook rejects it as a bad
// payload (no card is rendered). The status code is then mapped:
//
//   - 400 Bad Request -> active (the endpoint exists and validated our payload)
//   - 404 Not Found    -> inactive (webhook deleted or disabled)
//   - anything else     -> unverified (cannot decide non-destructively)
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return v.verify(ctx, raw, nil)
}

// VerificationRequestBudget declares the single non-destructive Teams probe.
func (v *Verifier) VerificationRequestBudget() int { return 1 }

// VerifyWithRequestGate admits the probe at its actual HTTP send point.
func (v *Verifier) VerifyWithRequestGate(
	ctx context.Context,
	raw detector.RawFinding,
	gate verifier.RequestGate,
) finding.VerificationResult {
	return v.verify(ctx, raw, gate)
}

func (v *Verifier) verify(
	ctx context.Context,
	raw detector.RawFinding,
	gate verifier.RequestGate,
) finding.VerificationResult {
	webhookURL := string(raw.Raw)
	if webhookURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty webhook URL",
		}
	}

	// An empty JSON object is a syntactically valid but semantically invalid
	// Teams payload (no "text"/"summary"): Teams returns 400 "Bad payload"
	// without delivering a card, so the probe is non-destructive.
	payload := []byte(`{}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(payload))
	if err != nil {
		// The webhook URL is itself the secret and may appear in the error text;
		// redact it before logging or returning.
		safeErr := httpx.RedactError(err, webhookURL)
		slog.ErrorContext(ctx, "teams verifier: failed to create request", slog.String("error", safeErr))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %s", safeErr),
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "leakwatch-verifier")

	client := v.httpClient
	if client == nil {
		client = httpx.Client()
	}
	if gate != nil {
		if rejection := gate(); rejection != nil {
			return *rejection
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		// A *url.Error from the transport embeds the full request URL, which is
		// the webhook secret; redact it before logging or returning.
		safeErr := httpx.RedactError(err, webhookURL)
		slog.ErrorContext(ctx, "teams verifier: request failed", slog.String("error", safeErr))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %s", safeErr),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// The shared client does not follow redirects; a redirect from a webhook
	// endpoint means the URL is wrong, never that the webhook is active.
	if httpx.IsRedirect(resp.StatusCode) {
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected redirect (status %d)", resp.StatusCode),
		}
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		// A real Teams webhook rejects our empty payload with 400 without
		// rendering a card. This is the positive, non-destructive signal.
		slog.InfoContext(ctx, "teams verifier: webhook rejected empty payload, treating as active")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "Teams webhook is active (rejected non-destructive empty payload)",
		}
	case http.StatusNotFound:
		slog.DebugContext(ctx, "teams verifier: webhook is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Teams webhook URL is not found or disabled",
		}
	default:
		// A genuine Teams webhook never accepts an empty payload (2xx), and any
		// other status is ambiguous. Avoid claiming active/inactive when we
		// cannot decide non-destructively.
		slog.DebugContext(
			ctx, "teams verifier: inconclusive response to non-destructive probe",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: fmt.Sprintf("inconclusive response to non-destructive probe (status %d)", resp.StatusCode),
		}
	}
}

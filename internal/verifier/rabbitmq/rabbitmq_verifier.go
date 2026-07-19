// Package rabbitmq provides a verifier for RabbitMQ connection strings.
// Live verification requires network access to the RabbitMQ server,
// so this verifier performs URL format validation only.
package rabbitmq

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "rabbitmq-connection-string"

// Verifier checks whether a RabbitMQ connection string has a valid URL format.
// It NEVER logs or persists raw password values.
//
// Note: This is a format-check verifier; it performs no live verification, so
// the result is always StatusUnverified. Live verification would require a
// network connection to the broker.
type Verifier struct{}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify checks if the detected RabbitMQ connection string has a valid AMQP URL format.
// Raw contains the full connection string (amqp://user:pass@host:port/vhost).
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	connStr := string(raw.Raw)
	if connStr == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty connection string",
		}
	}

	parsed, err := url.Parse(connStr)
	if err != nil {
		// NEVER log err.Error() here: net/url wraps parse failures in a
		// *url.Error whose message embeds the entire original input string
		// (including the plaintext password) via its %q-quoted URL field.
		// Log a generic message only; raw.Redacted is already safe to emit.
		slog.DebugContext(
			ctx, "rabbitmq verifier: failed to parse connection string",
			slog.String("redacted", raw.Redacted),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (cannot parse URL); live verification not supported",
		}
	}

	if parsed.Scheme != "amqp" && parsed.Scheme != "amqps" {
		slog.DebugContext(
			ctx, "rabbitmq verifier: unexpected scheme",
			slog.String("scheme", parsed.Scheme),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (scheme is not amqp or amqps); live verification not supported",
		}
	}

	if parsed.User == nil || parsed.User.Username() == "" {
		slog.DebugContext(ctx, "rabbitmq verifier: missing user credentials")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (missing user credentials in URL); live verification not supported",
		}
	}

	if parsed.Host == "" {
		slog.DebugContext(ctx, "rabbitmq verifier: missing host")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (missing host in URL); live verification not supported",
		}
	}

	extra := map[string]string{
		"host": parsed.Hostname(),
		"user": parsed.User.Username(),
	}

	slog.DebugContext(
		ctx, "rabbitmq verifier: connection string format validated",
		slog.String("host", parsed.Hostname()),
		slog.String("user", parsed.User.Username()),
	)

	return finding.VerificationResult{
		Status:    finding.StatusUnverified,
		Message:   "format valid; live verification not supported (requires network access)",
		ExtraData: extra,
	}
}

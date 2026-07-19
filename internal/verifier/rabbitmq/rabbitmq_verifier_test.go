package rabbitmq

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerifier_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "rabbitmq-connection-string", v.Type())
}

func TestVerify_ValidAMQPURL_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqp://admin:s3cret@rabbitmq.example.com:5672/"),
		Redacted:   "amqp://admin:****@rabbitmq.example.com:5672/",
	}

	result := v.Verify(context.Background(), raw)

	// Format-only verifier: a valid URL does not prove the broker is reachable
	// or the credentials active, so the status must be Unverified.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Equal(t, "rabbitmq.example.com", result.ExtraData["host"])
	assert.Equal(t, "admin", result.ExtraData["user"])
}

func TestVerify_ValidAMQPSURL_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqps://myuser:mypass@broker.cloud.io:5671/production"),
		Redacted:   "amqps://myuser:****@broker.cloud.io:5671/production",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "broker.cloud.io", result.ExtraData["host"])
	assert.Equal(t, "myuser", result.ExtraData["user"])
}

func TestVerify_WrongScheme_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("http://admin:pass@rabbitmq.example.com:5672/"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	// Format invalid must NOT be VerifiedInactive: no provider was contacted.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_MissingCredentials_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqp://rabbitmq.example.com:5672/"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_MissingHost_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqp://user:pass@"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_EmptyInput_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty connection string", result.Message)
}

func TestVerify_InvalidURL_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("://not-a-valid-url"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

// TestVerify_MalformedURL_NeverLeaksRawSecret guards the secret-safety
// regression: net/url wraps parse failures in a *url.Error whose Error() embeds
// the entire input string (including the plaintext password). The verifier must
// never route that error text to a logger, and the raw password must appear
// neither in any emitted log line nor in the returned VerificationResult.
func TestVerify_MalformedURL_NeverLeaksRawSecret(t *testing.T) {
	const password = "s3cr3tP4ss" // synthetic

	// An unescaped "%zz" in the password makes url.Parse fail with a *url.Error
	// that embeds the whole connection string.
	connStr := "amqp://user:" + password + "%zz@host:5672/vhost"

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	v := &Verifier{}
	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(connStr),
		Redacted:   "amqp://user:****@host:5672/vhost",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")

	logOutput := buf.String()
	assert.NotEmpty(t, logOutput, "expected a debug log line to be emitted")
	assert.NotContains(t, logOutput, password, "raw password leaked into log output")
	assert.NotContains(t, logOutput, connStr, "raw connection string leaked into log output")

	assert.NotContains(t, result.Message, password, "raw password leaked into result message")
	for k, val := range result.ExtraData {
		assert.NotContains(t, val, password, "raw password leaked into ExtraData[%s]", k)
	}
}

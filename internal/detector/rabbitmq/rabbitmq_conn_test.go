package rabbitmq

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "rabbitmq-connection-string", d.ID())
	assert.Equal(t, "RabbitMQ Connection String", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "amqp with user and password",
			input:    "amqp://guest:guest@rabbitmq.example.com:5672/",
			expected: 1,
			redacted: "amqp://guest:****@rabbitmq.example.com:5672/",
		},
		{
			name:     "amqps TLS connection",
			input:    "amqps://admin:s3cretP4ss@mq.example.com:5671/production",
			expected: 1,
			redacted: "amqps://admin:****@mq.example.com:5671/production",
		},
		{
			name:     "amqp in env var",
			input:    `RABBITMQ_URL=amqp://user:testpass@localhost:5672/vhost`,
			expected: 1,
			redacted: "amqp://user:****@localhost:5672/vhost",
		},
		{
			name:     "amqp in JSON config",
			input:    `{"rabbitmq_url": "amqp://app:dbpass123@rabbit-host:5672/"}`,
			expected: 1,
			redacted: "amqp://app:****@rabbit-host:5672/",
		},
		{
			name:     "multiple amqp URLs",
			input:    "amqp://a:pass1@host1:5672/ amqps://b:pass2@host2:5671/",
			expected: 2,
		},
	}

	d := &Detector{}
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

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "amqp URL without credentials",
			input: "amqp://localhost:5672/",
		},
		{
			name:  "http URL not amqp",
			input: "http://example.com/api/v1",
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

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

func TestRedactPassword_VariousFormats(t *testing.T) {
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
			// No userinfo: fail safe and mask everything but the scheme.
			name:     "no credentials in URL",
			input:    "amqp://host:5672/",
			expected: "amqp://****",
		},
		{
			name:     "user without password",
			input:    "amqp://user@host:5672/",
			expected: "amqp://user:****@host:5672/",
		},
		{
			name:     "amqps TLS scheme",
			input:    "amqps://admin:secret@host:5671/vhost",
			expected: "amqps://admin:****@host:5671/vhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.RedactURLPassword(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRedactPassword_EmbeddedCredentialInPath_MasksInsteadOfLeaking guards the
// fail-open regression: the detector regex only excludes whitespace and quotes,
// so a whitespace-free run can carry a "user:pass@" credential in the path or
// query while net/url parses the authority as having no userinfo.
// detector.RedactURLPassword must MASK such a match, never return the raw
// string with the cleartext credential.
func TestRedactPassword_EmbeddedCredentialInPath_MasksInsteadOfLeaking(t *testing.T) {
	// Synthetic credential embedded in the query, not the authority.
	raw := "amqp://simplehost/path?redirect=http://user:s3cr3tP4ss@evil.com"

	result := detector.RedactURLPassword(raw)

	assert.Equal(t, "amqp://****", result)
	assert.NotContains(t, result, "s3cr3tP4ss")
	assert.NotContains(t, result, "user:")
	assert.NotEqual(t, raw, result)
}

func TestDetector_Scan_Raw_DoesNotAliasInputBuffer(t *testing.T) {
	input := []byte("amqp://guest:guest@rabbitmq.example.com:5672/")

	d := &Detector{}
	findings := d.Scan(context.Background(), input)
	require.Len(t, findings, 1)

	raw := findings[0].Raw
	original := string(raw)

	for i := range input {
		input[i] = 'x'
	}

	assert.Equal(t, original, string(raw))
}

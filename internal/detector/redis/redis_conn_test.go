package redis

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "redis-connection-string", d.ID())
	assert.Equal(t, "Redis Connection String", d.Description())
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
			name:     "redis with user and password",
			input:    "redis://default:s3cretP4ss@cache.example.com:6379/0",
			expected: 1,
			redacted: "redis://default:****@cache.example.com:6379/0",
		},
		{
			name:     "rediss TLS connection",
			input:    "rediss://admin:TLSpa55w0rd@redis.example.com:6380/1",
			expected: 1,
			redacted: "rediss://admin:****@redis.example.com:6380/1",
		},
		{
			name:     "redis in env var",
			input:    `REDIS_URL=redis://user:testpass@localhost:6379/0`,
			expected: 1,
			redacted: "redis://user:****@localhost:6379/0",
		},
		{
			name:     "redis in JSON config",
			input:    `{"redis_url": "redis://app:dbpass123@redis-host:6379/2"}`,
			expected: 1,
			redacted: "redis://app:****@redis-host:6379/2",
		},
		{
			name:     "multiple redis URLs",
			input:    "redis://a:pass1@host1:6379/0 rediss://b:pass2@host2:6380/1",
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
			name:  "redis URL without credentials",
			input: "redis://localhost:6379/0",
		},
		{
			name:  "http URL not redis",
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
			input:    "redis://user:password@host:6379/0",
			expected: "redis://user:****@host:6379/0",
		},
		{
			// No userinfo: fail safe and mask everything but the scheme.
			name:     "no credentials in URL",
			input:    "redis://host:6379/0",
			expected: "redis://****",
		},
		{
			name:     "user without password",
			input:    "redis://user@host:6379/0",
			expected: "redis://user:****@host:6379/0",
		},
		{
			name:     "rediss TLS scheme",
			input:    "rediss://admin:secret@host:6380/1",
			expected: "rediss://admin:****@host:6380/1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactPassword(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRedactPassword_EmbeddedCredentialInPath_MasksInsteadOfLeaking guards the
// fail-open regression: the detector regex only excludes whitespace and quotes,
// so a whitespace-free run can carry a "user:pass@" credential in the path or
// query while net/url parses the authority as having no userinfo. redactPassword
// must MASK such a match, never return the raw string with the cleartext credential.
func TestRedactPassword_EmbeddedCredentialInPath_MasksInsteadOfLeaking(t *testing.T) {
	// Synthetic credential embedded in the query, not the authority.
	raw := "redis://simplehost/path?redirect=http://user:s3cr3tP4ss@evil.com"

	result := redactPassword(raw)

	assert.Equal(t, "redis://****", result)
	assert.NotContains(t, result, "s3cr3tP4ss")
	assert.NotContains(t, result, "user:")
	assert.NotEqual(t, raw, result)
}

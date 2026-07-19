package ftp

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
	assert.Equal(t, "ftp-credentials", d.ID())
	assert.Equal(t, "FTP/SFTP Credentials", d.Description())
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
			name:     "ftp with user and password",
			input:    "ftp://deploy:s3cretP4ss@ftp.example.com:21/uploads",
			expected: 1,
			redacted: "ftp://deploy:****@ftp.example.com:21/uploads",
		},
		{
			name:     "sftp connection",
			input:    "sftp://admin:P@ssw0rd@sftp.example.com:22/data",
			expected: 1,
			redacted: "sftp://admin:****@sftp.example.com:22/data",
		},
		{
			name:     "ftps TLS connection",
			input:    "ftps://user:tlspass@ftps.example.com:990/secure",
			expected: 1,
			redacted: "ftps://user:****@ftps.example.com:990/secure",
		},
		{
			name:     "ftp in env var",
			input:    `FTP_URL=ftp://uploader:testpass@localhost:21/pub`,
			expected: 1,
			redacted: "ftp://uploader:****@localhost:21/pub",
		},
		{
			name:     "ftp in JSON config",
			input:    `{"ftp_url": "ftp://app:dbpass123@ftp-host:21/files"}`,
			expected: 1,
			redacted: "ftp://app:****@ftp-host:21/files",
		},
		{
			name:     "multiple ftp URLs",
			input:    "ftp://a:pass1@host1:21/dir sftp://b:pass2@host2:22/dir",
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
			name:  "ftp URL without credentials",
			input: "ftp://ftp.example.com/pub",
		},
		{
			name:  "http URL not ftp",
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
			name:     "standard ftp user:pass@host",
			input:    "ftp://user:password@host:21/path",
			expected: "ftp://user:****@host:21/path",
		},
		{
			// No userinfo: fail safe and mask everything but the scheme.
			name:     "no credentials in URL",
			input:    "ftp://host:21/path",
			expected: "ftp://****",
		},
		{
			name:     "user without password",
			input:    "ftp://user@host:21/path",
			expected: "ftp://user:****@host:21/path",
		},
		{
			name:     "sftp scheme",
			input:    "sftp://admin:secret@host:22/data",
			expected: "sftp://admin:****@host:22/data",
		},
		{
			name:     "ftps scheme",
			input:    "ftps://admin:secret@host:990/data",
			expected: "ftps://admin:****@host:990/data",
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
// fail-open regression: the detector regex only excludes whitespace and
// quotes, so a whitespace-free run can carry a "user:pass@" credential in the
// path or query while net/url parses the authority as having no userinfo.
// RedactURLPassword must MASK such a match, never return the raw string with
// the cleartext credential.
func TestRedactPassword_EmbeddedCredentialInPath_MasksInsteadOfLeaking(t *testing.T) {
	raw := "ftp://simplehost/path?redirect=http://user:s3cr3tP4ss@evil.com"

	result := detector.RedactURLPassword(raw)

	assert.Equal(t, "ftp://****", result)
	assert.NotContains(t, result, "s3cr3tP4ss")
	assert.NotContains(t, result, "user:")
	assert.NotEqual(t, raw, result)
}

func TestDetector_Scan_Raw_DoesNotAliasInputBuffer(t *testing.T) {
	input := []byte("ftp://deploy:s3cretP4ss@ftp.example.com:21/uploads")

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

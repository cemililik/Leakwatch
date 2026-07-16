package ldap

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "ldap-credentials", d.ID())
	assert.Equal(t, "LDAP/LDAPS Bind Credentials", d.Description())
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
			name:     "ldap with bind credentials",
			input:    "ldap://cn=admin:s3cretP4ss@ldap.example.com:389/dc=example,dc=com",
			expected: 1,
			redacted: "ldap://cn=admin:****@ldap.example.com:389/dc=example,dc=com",
		},
		{
			name:     "ldaps TLS connection",
			input:    "ldaps://uid=svc:P@ssw0rd@ldap.example.com:636/ou=users,dc=example,dc=com",
			expected: 1,
			redacted: "ldaps://uid=svc:****@ldap.example.com:636/ou=users,dc=example,dc=com",
		},
		{
			name:     "ldap in env var",
			input:    `LDAP_URL=ldap://admin:testpass@localhost:389/`,
			expected: 1,
			redacted: "ldap://admin:****@localhost:389/",
		},
		{
			name:     "ldap in JSON config",
			input:    `{"ldap_url": "ldap://bind:dbpass123@ldap-host:389/dc=corp"}`,
			expected: 1,
			redacted: "ldap://bind:****@ldap-host:389/dc=corp",
		},
		{
			name:     "multiple ldap URLs",
			input:    "ldap://a:pass1@host1:389/ ldaps://b:pass2@host2:636/",
			expected: 2,
		},
		{
			name:     "uppercase LDAP scheme",
			input:    "LDAP://admin:s3cretP4ss@ldap.example.com:389/dc=example,dc=com",
			expected: 1,
			redacted: "ldap://admin:****@ldap.example.com:389/dc=example,dc=com",
		},
		{
			name:     "mixed case LDAPS scheme",
			input:    "LdApS://uid=svc:P@ssw0rd@ldap.example.com:636/ou=users,dc=example,dc=com",
			expected: 1,
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
			name:  "ldap URL without credentials",
			input: "ldap://ldap.example.com:389/dc=example,dc=com",
		},
		{
			name:  "http URL not ldap",
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
			name:     "standard ldap user:pass@host",
			input:    "ldap://admin:password@host:389/",
			expected: "ldap://admin:****@host:389/",
		},
		{
			name:     "no credentials in URL",
			input:    "ldap://host:389/",
			expected: "ldap://host:389/",
		},
		{
			name:     "user without password",
			input:    "ldap://admin@host:389/",
			expected: "ldap://admin:****@host:389/",
		},
		{
			name:     "ldaps TLS scheme",
			input:    "ldaps://admin:secret@host:636/",
			expected: "ldaps://admin:****@host:636/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactPassword(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDetector_Scan_RawIsClonedNotAliased verifies Raw does not alias the
// scanned chunk buffer (memory/aliasing hardening).
func TestDetector_Scan_RawIsClonedNotAliased(t *testing.T) {
	data := []byte("ldap://cn=admin:s3cretP4ss@ldap.example.com:389/dc=example,dc=com")

	d := &Detector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawBefore := string(findings[0].Raw)
	for i := range data {
		data[i] = 'x'
	}
	assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
}

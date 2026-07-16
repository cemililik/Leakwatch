package dbconn

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionString_Metadata(t *testing.T) {
	d := &ConnectionString{}
	assert.Equal(t, "database-connection-string", d.ID())
	assert.Equal(t, "Database Connection String", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestConnectionString_Scan_MatchesValidStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "postgres connection string",
			input:    "postgres://admin:TESTPASS@localhost:5432/mydb",
			expected: 1,
			redacted: "postgres://admin:****@localhost:5432/mydb",
		},
		{
			name:     "mysql connection string",
			input:    "mysql://root:TESTPWD@db.example.com:3306/app",
			expected: 1,
			redacted: "mysql://root:****@db.example.com:3306/app",
		},
		{
			name:     "mongodb connection string",
			input:    "mongodb://user:pass1234@mongo.example.com:27017/test",
			expected: 1,
			redacted: "mongodb://user:****@mongo.example.com:27017/test",
		},
		{
			name:     "mongodb+srv connection string",
			input:    "mongodb+srv://user:pass1234@cluster0.example.net/mydb",
			expected: 1,
			redacted: "mongodb+srv://user:****@cluster0.example.net/mydb",
		},
		{
			name:     "redis connection string",
			input:    "redis://default:redispass@cache.example.com:6379/0",
			expected: 1,
			redacted: "redis://default:****@cache.example.com:6379/0",
		},
		{
			name:     "connection string in env var",
			input:    `DATABASE_URL=postgres://admin:TESTPASS@localhost:5432/mydb`,
			expected: 1,
		},
		{
			name:     "connection string in JSON",
			input:    `{"dsn": "mysql://root:TESTPWD@db.example.com:3306/app"}`,
			expected: 1,
		},
		{
			name:     "multiple connection strings",
			input:    "postgres://admin:TESTPASS@localhost:5432/mydb mysql://root:TESTPWD@db.example.com:3306/app",
			expected: 2,
		},
		{
			name:     "connection string in large text",
			input:    strings.Repeat("x", 10000) + "postgres://admin:TESTPASS@localhost:5432/mydb" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &ConnectionString{}
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

func TestConnectionString_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "http URL not a database",
			input: "http://example.com/api/v1",
		},
		{
			name:  "database URL without credentials",
			input: "postgres://localhost:5432/mydb",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "bare user@host without password is not flagged",
			input: "postgres://readonly_user@db.internal.example.com:5432/analytics",
		},
		{
			name:  "URI-style placeholder password is skipped",
			input: "postgres://admin:changeme@localhost:5432/mydb",
		},
	}

	d := &ConnectionString{}
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
			input:    "postgres://user:password@host:5432/db",
			expected: "postgres://user:****@host:5432/db",
		},
		{
			name:     "no credentials in URL",
			input:    "postgres://host:5432/db",
			expected: "postgres://host:5432/db",
		},
		{
			name:     "user without password",
			input:    "postgres://user@host:5432/db",
			expected: "postgres://user:****@host:5432/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactPassword(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedactPassword_MalformedURL(t *testing.T) {
	// url.Parse rarely fails outright; force the error path with a control
	// character which the parser rejects.
	result := redactPassword("postgres://user:pass@host\x7f:5432/db")
	assert.Equal(t, "****", result, "malformed URL should be redacted entirely")
}

func TestConnectionString_Scan_MatchesADONet(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		contains string
	}{
		{
			name:     "ADO.NET Host=...Password=...",
			input:    "Host=localhost;Database=mydb;Username=user;Password=secret123",
			expected: 1,
			contains: "Password=****",
		},
		{
			name:     "ADO.NET Server=...Pwd=...",
			input:    "Server=db.example.com;Database=app;User Id=sa;Pwd=S3cr3t!",
			expected: 1,
			contains: "Pwd=****",
		},
		{
			name:     "ADO.NET Data Source",
			input:    "Data Source=sql.example.com;Initial Catalog=app;User ID=admin;Password=hunter2",
			expected: 1,
			contains: "Password=****",
		},
		{
			name:     "case-insensitive PASSWORD",
			input:    "Host=localhost;Database=app;User=admin;PASSWORD=hunter2",
			expected: 1,
			contains: "PASSWORD=****",
		},
		{
			name:     "Password field before Data Source (reverse field order)",
			input:    "Password=hunter2;Persist Security Info=True;User ID=user;Initial Catalog=db;Data Source=server",
			expected: 1,
			contains: "Password=****",
		},
		{
			name:     "Pwd field before Server (reverse field order)",
			input:    "Pwd=S3cr3t!;User Id=sa;Server=db.example.com",
			expected: 1,
			contains: "Pwd=****",
		},
	}

	d := &ConnectionString{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			require.Len(t, findings, tt.expected)
			assert.Contains(t, findings[0].Redacted, tt.contains)
		})
	}
}

func TestConnectionString_Scan_SkipsADONetPlaceholders(t *testing.T) {
	placeholders := []string{
		"Host=localhost;Database=mydb;User=admin;Password=changeme",
		"Server=db;Database=app;User=admin;Password=your_password",
		"Data Source=sql;Initial Catalog=app;User ID=admin;Password=TODO",
		"Host=localhost;Database=app;User=admin;Pwd=xxxxxxxx",
		"Host=localhost;Database=app;User=admin;Password=placeholder",
		// Reverse field order (Password before the host-ish field) must also
		// be checked against the placeholder allowlist.
		"Password=changeme;User Id=sa;Server=db.example.com",
	}

	d := &ConnectionString{}
	for _, input := range placeholders {
		t.Run(input, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(input))
			assert.Empty(t, findings, "placeholder password should not be reported as a finding")
		})
	}
}

func TestRedactADONet(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Password key",
			input:    "Host=localhost;Database=mydb;User=admin;Password=secret123",
			expected: "Host=localhost;Database=mydb;User=admin;Password=****",
		},
		{
			name:     "Pwd shorthand",
			input:    "Server=db;User=admin;Pwd=secret123",
			expected: "Server=db;User=admin;Pwd=****",
		},
		{
			name:     "lowercase password",
			input:    "Server=db;User=admin;password=secret123",
			expected: "Server=db;User=admin;password=****",
		},
		{
			name:     "no password to redact",
			input:    "Server=db;User=admin",
			expected: "Server=db;User=admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, redactADONet(tt.input))
		})
	}
}

func TestIsPlaceholderPassword(t *testing.T) {
	placeholders := []string{
		"change_me", "changeme", "your_password", "your-password",
		"replace_me", "xxxxxxxx", "TODO", "FIXME", "placeholder",
		"example", "password", "secret", "change_me_in_production",
		// Case insensitive
		"CHANGEME", "Password", "SECRET",
	}
	for _, p := range placeholders {
		t.Run("placeholder "+p, func(t *testing.T) {
			assert.True(t, isPlaceholderPassword(p), "%q should be recognized as a placeholder", p)
		})
	}

	realSecrets := []string{
		"S3cr3t!", "hunter2", "Tr0ub4dor&3", "correct horse battery staple",
		"a1b2c3d4e5", "MyRealP@ssw0rd",
	}
	for _, s := range realSecrets {
		t.Run("real "+s, func(t *testing.T) {
			assert.False(t, isPlaceholderPassword(s), "%q should NOT be a placeholder", s)
		})
	}
}

// TestConnectionString_Scan_RawIsClonedNotAliased verifies Raw does not alias
// the scanned chunk buffer, for both the URI and ADO.NET match paths
// (memory/aliasing hardening).
func TestConnectionString_Scan_RawIsClonedNotAliased(t *testing.T) {
	d := &ConnectionString{}

	t.Run("URI-style match", func(t *testing.T) {
		data := []byte("postgres://admin:TESTPASS@localhost:5432/mydb")
		findings := d.Scan(context.Background(), data)
		require.Len(t, findings, 1)

		rawBefore := string(findings[0].Raw)
		for i := range data {
			data[i] = 'x'
		}
		assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
	})

	t.Run("ADO.NET-style match", func(t *testing.T) {
		data := []byte("Host=localhost;Database=mydb;Username=user;Password=secret123")
		findings := d.Scan(context.Background(), data)
		require.Len(t, findings, 1)

		rawBefore := string(findings[0].Raw)
		for i := range data {
			data[i] = 'x'
		}
		assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
	})
}

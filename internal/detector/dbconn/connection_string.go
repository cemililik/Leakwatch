// Package dbconn provides a detector for database connection strings.
package dbconn

import (
	"bytes"
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// connStringPattern requires a colon-delimited password between the username
// and host (user:pass@host) so that bare, passwordless credentials (common in
// IAM/passwordless auth, e.g. "postgres://readonly_user@host/db") are not
// flagged and redactPassword never has to fabricate a redacted password that
// was never present.
var connStringPattern = regexp.MustCompile(`(postgres|mysql|mongodb(\+srv)?|redis)://[^\s'"@:]+:[^\s'"@]+@[^\s'"]+`)

// adonetPattern matches ADO.NET style connection strings with a Password/Pwd
// field, independent of whether it appears before or after the host-ish
// (Host/Server/Data Source) field — ADO.NET connection strings are unordered
// key=value pairs, and Password commonly appears first in builder-generated
// or hand-copied strings. Capture group 1 holds the password when the
// host-ish field comes first; group 2 holds it when Password/Pwd comes first.
// Example (host first):     Host=localhost;Database=mydb;Username=user;Password=secret123
// Example (password first): Password=secret123;Persist Security Info=True;Data Source=server
var adonetPattern = regexp.MustCompile(
	`(?i)(?:(?:Host|Server|Data Source)=[^;]+;[^'"]*(?:Password|Pwd)=([^;'"\s]+)` +
		`|(?:Password|Pwd)=([^;'"\s]+)[^'"]*;[^'"]*(?:Host|Server|Data Source)=)`,
)

// redactADONetPattern matches Password/Pwd assignments for redaction.
// Hoisted to package scope so it is compiled once at init, not per call.
var redactADONetPattern = regexp.MustCompile(`(?i)(Password|Pwd)=([^;'"\s]+)`)

// ConnectionString detects database connection strings containing credentials.
type ConnectionString struct{}

// ID returns the unique identifier of the database connection string detector.
func (d *ConnectionString) ID() string { return "database-connection-string" }

// Description returns a human-readable description of the database connection string detector.
func (d *ConnectionString) Description() string { return "Database Connection String" }

// Keywords returns the Aho-Corasick pre-filter keywords for database connection string detection.
func (d *ConnectionString) Keywords() []string {
	return []string{
		"postgres://", "mysql://", "mongodb://", "mongodb+srv://", "redis://",
		"Password=", "password=", "Pwd=", "pwd=",
	}
}

// Severity returns the default severity level for database connection string findings.
func (d *ConnectionString) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for database connection string patterns.
// The password portion of the URL is redacted in the finding output.
func (d *ConnectionString) Scan(_ context.Context, data []byte) []detector.RawFinding {
	var findings []detector.RawFinding

	// URI-style connection strings (postgres://user:pass@host)
	for _, match := range connStringPattern.FindAll(data, -1) {
		// Skip placeholder passwords, matching the ADO.NET path's behavior.
		if u, err := url.Parse(string(match)); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok && isPlaceholderPassword(pw) {
				continue
			}
		}
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redactPassword(string(match)),
		})
	}

	// ADO.NET style connection strings (Host=...;Password=... in either field order)
	for _, match := range adonetPattern.FindAllSubmatch(data, -1) {
		if len(match) < 3 {
			continue
		}
		password := string(match[1])
		if password == "" {
			password = string(match[2])
		}
		// Skip placeholder passwords
		if isPlaceholderPassword(password) {
			continue
		}
		fullMatch := string(match[0])
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match[0]),
			Redacted:   redactADONet(fullMatch),
		})
	}

	return findings
}

// redactPassword masks the password portion in a database connection URL.
// Uses net/url.Parse for proper parsing, then reconstructs with masked password.
func redactPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "****"
	}
	if u.User == nil {
		return raw // No credentials to redact
	}
	username := u.User.Username()
	// Reconstruct manually to avoid URL-encoding of **** characters.
	u.User = nil
	return u.Scheme + "://" + username + ":****@" + u.Host + u.RequestURI()
}

// redactADONet masks the password in an ADO.NET style connection string.
func redactADONet(raw string) string {
	return redactADONetPattern.ReplaceAllString(raw, "${1}=****")
}

// isPlaceholderPassword checks if a password is a common placeholder value.
// Comparison is case-insensitive — placeholder entries are stored in lowercase
// and the input is lowercased before comparison.
func isPlaceholderPassword(password string) bool {
	placeholders := []string{
		"change_me", "changeme", "your_password", "your-password",
		"replace_me", "xxxxxxxx", "todo", "fixme", "placeholder",
		"example", "password", "secret", "change_me_in_production",
	}
	lower := strings.ToLower(password)
	for _, p := range placeholders {
		if lower == p {
			return true
		}
	}
	return false
}

func init() {
	detector.Register(&ConnectionString{})
}

package github

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errWriter always fails, to exercise the Format write-error path.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestFormatter_Format_EmptyFindings_WritesNothing(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestFormatter_Format_SingleFinding_EmitsErrorAnnotationWithFileAndLine(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				SourceType: "filesystem",
				FilePath:   "config/prod.yaml",
				Line:       42,
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "::error "), "critical maps to ::error, got %q", out)
	assert.Contains(t, out, "file=config/prod.yaml")
	assert.Contains(t, out, "line=42")
	assert.Contains(t, out, "title=Leakwatch%3A aws-access-key-id") // ':' escaped in property
	assert.Contains(t, out, "AKIA****MPLE")
	assert.True(t, strings.HasSuffix(out, "\n"), "command must end with newline")
	assert.Equal(t, 1, strings.Count(out, "\n"), "exactly one annotation expected")
}

func TestFormatter_Format_SeverityMapsToAnnotationLevel(t *testing.T) {
	tests := []struct {
		name      string
		severity  finding.Severity
		wantLevel string
	}{
		{"critical -> error", finding.SeverityCritical, "::error "},
		{"high -> warning", finding.SeverityHigh, "::warning "},
		{"medium -> notice", finding.SeverityMedium, "::notice "},
		{"low -> notice", finding.SeverityLow, "::notice "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Formatter{}
			var buf bytes.Buffer
			err := f.Format(&buf, []finding.Finding{{
				DetectorID:     "generic-api-key",
				Severity:       tt.severity,
				Redacted:       "abc****xyz",
				SourceMetadata: finding.SourceMetadata{FilePath: "a.txt", Line: 1},
			}})
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(buf.String(), tt.wantLevel),
				"want prefix %q, got %q", tt.wantLevel, buf.String())
		})
	}
}

func TestFormatter_Format_NoFilePath_EmitsRunLevelAnnotation(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	// Slack/container findings may have no file path.
	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "slack-token",
		Severity:       finding.SeverityHigh,
		Redacted:       "xoxb-****",
		SourceMetadata: finding.SourceMetadata{SourceType: "slack"},
	}})
	require.NoError(t, err)

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "::warning "))
	assert.NotContains(t, out, "file=")
	assert.NotContains(t, out, "line=")
	assert.Contains(t, out, "title=Leakwatch%3A slack-token")
}

func TestFormatter_Format_FilePathWithoutLine_OmitsLineProperty(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "private-key",
		Severity:       finding.SeverityHigh,
		Redacted:       "----****----",
		SourceMetadata: finding.SourceMetadata{FilePath: "id_rsa"},
	}})
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "file=id_rsa")
	assert.NotContains(t, out, "line=")
}

func TestFormatter_Format_VerifiedActive_MessageFlagsIncident(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "github-token",
		Severity:       finding.SeverityCritical,
		Redacted:       "ghp_****",
		SourceMetadata: finding.SourceMetadata{FilePath: ".env", Line: 3},
		Verification:   finding.VerificationResult{Status: finding.StatusVerifiedActive},
	}})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "verified ACTIVE")
}

func TestFormatter_Format_EscapesPropertiesAndData(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	// A file path with characters that delimit workflow-command properties, and
	// a redacted value containing a newline, must be percent-encoded so the
	// command is not broken or injectable.
	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "generic-api-key",
		Severity:       finding.SeverityLow,
		Redacted:       "line1\nline2",
		SourceMetadata: finding.SourceMetadata{FilePath: "weird,name:file.txt", Line: 7},
	}})
	require.NoError(t, err)

	out := buf.String()
	// Property escaping: ',' -> %2C and ':' -> %3A inside file=...
	assert.Contains(t, out, "file=weird%2Cname%3Afile.txt")
	// Data escaping: newline -> %0A inside the message payload.
	assert.Contains(t, out, "line1%0Aline2")
	// The raw delimiters must not survive in the encoded path.
	assert.NotContains(t, out, "weird,name:file.txt")
	// Output is still a single line (no literal newline injected mid-command).
	assert.Equal(t, 1, strings.Count(out, "\n"))
}

func TestFormatter_Format_NeverEmitsRawSecret(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	const raw = "this-raw-value-must-never-be-emitted"
	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "aws-access-key-id",
		Severity:       finding.SeverityCritical,
		Raw:            raw,
		Redacted:       "AKIA****ALUE",
		SourceMetadata: finding.SourceMetadata{FilePath: "a.txt", Line: 1},
	}})
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), raw, "raw secret must never appear in annotations")
}

func TestFormatter_Format_MultipleFindings_OneCommandPerLine(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{DetectorID: "aws-access-key-id", Severity: finding.SeverityCritical, Redacted: "AKIA****", SourceMetadata: finding.SourceMetadata{FilePath: "a", Line: 1}},
		{DetectorID: "jwt", Severity: finding.SeverityHigh, Redacted: "eyJ****", SourceMetadata: finding.SourceMetadata{FilePath: "b", Line: 2}},
		{DetectorID: "generic-api-key", Severity: finding.SeverityMedium, Redacted: "x****y", SourceMetadata: finding.SourceMetadata{FilePath: "c", Line: 3}},
	}
	err := f.Format(&buf, findings)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	require.Len(t, lines, 3)
	assert.True(t, strings.HasPrefix(lines[0], "::error "))
	assert.True(t, strings.HasPrefix(lines[1], "::warning "))
	assert.True(t, strings.HasPrefix(lines[2], "::notice "))
}

func TestFormatter_Format_VerifiedInactive_MessageNotesInactive(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "stripe-api-key-test",
		Severity:       finding.SeverityMedium,
		Redacted:       "sk_test_****",
		SourceMetadata: finding.SourceMetadata{FilePath: ".env", Line: 9},
		Verification:   finding.VerificationResult{Status: finding.StatusVerifiedInactive},
	}})
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "verified inactive")
	assert.NotContains(t, out, "ACTIVE")
}

func TestFormatter_Format_UnknownSeverity_FallsBackToNotice(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	// A severity outside the known set must not panic and should default to the
	// lowest annotation level.
	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "generic-api-key",
		Severity:       finding.Severity(99),
		Redacted:       "x****y",
		SourceMetadata: finding.SourceMetadata{FilePath: "a.txt", Line: 1},
	}})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(buf.String(), "::notice "))
}

func TestFormatter_Format_VerifiedActiveLowSeverity_ElevatedToError(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	// A live-verified secret is an incident even at a low nominal severity, so it
	// must be emitted as ::error, not ::notice.
	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "generic-api-key",
		Severity:       finding.SeverityLow,
		Redacted:       "abc****xyz",
		SourceMetadata: finding.SourceMetadata{FilePath: "a.txt", Line: 1},
		Verification:   finding.VerificationResult{Status: finding.StatusVerifiedActive},
	}})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(buf.String(), "::error "), "verified-active must elevate to error, got %q", buf.String())
}

func TestFormatter_Format_VerifyError_NoVerdictSuffix(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "github-token",
		Severity:       finding.SeverityHigh,
		Redacted:       "ghp_****",
		SourceMetadata: finding.SourceMetadata{FilePath: ".env", Line: 3},
		Verification:   finding.VerificationResult{Status: finding.StatusVerifyError},
	}})
	require.NoError(t, err)

	out := buf.String()
	assert.NotContains(t, out, "ACTIVE")
	assert.NotContains(t, out, "inactive")
	// A verify error is not a confirmed-active verdict, so it stays a warning.
	assert.True(t, strings.HasPrefix(out, "::warning "))
}

func TestFormatter_Format_EscapesPercentAndCarriageReturn(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	// '%' must be encoded first (so the encodings below are not double-escaped),
	// and a carriage return must become %0D.
	err := f.Format(&buf, []finding.Finding{{
		DetectorID:     "generic-api-key",
		Severity:       finding.SeverityLow,
		Redacted:       "a%b\rc",
		SourceMetadata: finding.SourceMetadata{FilePath: "f.txt", Line: 1},
	}})
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "a%25b%0Dc")
	assert.NotContains(t, out, "%2525", "percent must not be double-escaped")
}

func TestFormatter_Format_ControlBytesInAttackerFields_StrippedFromOutput(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{{
		DetectorID: "custom-rule\x1b[2J",
		Severity:   finding.SeverityHigh,
		Redacted:   "AKIA\x1b]0;pwnedMPLE",
		SourceMetadata: finding.SourceMetadata{
			FilePath: "evil\x1b[31m.go",
			Line:     1,
		},
	}})
	require.NoError(t, err)

	out := buf.String()
	assert.NotContains(t, out, "\x1b",
		"ESC bytes embedded in DetectorID, FilePath, or Redacted must never reach the workflow-command stream")
}

func TestFormatter_Format_WriteError_IsWrapped(t *testing.T) {
	f := &Formatter{}
	err := f.Format(errWriter{}, []finding.Finding{{
		DetectorID:     "aws-access-key-id",
		Severity:       finding.SeverityCritical,
		Redacted:       "AKIA****",
		SourceMetadata: finding.SourceMetadata{FilePath: "a", Line: 1},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub annotations")
	assert.Contains(t, err.Error(), "disk full")
}

func TestFormatter_FileExtension_ReturnsTXT(t *testing.T) {
	f := &Formatter{}
	assert.Equal(t, ".txt", f.FileExtension())
}

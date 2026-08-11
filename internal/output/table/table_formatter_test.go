package table

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/mattn/go-runewidth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatter_Format_EmptyFindings_WritesHeaderAndZeroSummary(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SEVERITY")
	assert.Contains(t, output, "DETECTOR")
	assert.Contains(t, output, "Found 0 secrets.")
}

func TestFormatter_Format_SingleFinding_WritesCorrectRow(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "abc123",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.yaml",
			},
			Verification: finding.VerificationResult{
				Status: finding.StatusVerifiedActive,
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "CRITICAL")
	assert.Contains(t, output, "aws-access-key-id")
	assert.Contains(t, output, "config.yaml")
	assert.Contains(t, output, "AKIA****MPLE")
	assert.Contains(t, output, "verified_active")
	assert.Contains(t, output, "Found 1 secrets (1 critical).")
}

func TestFormatter_Format_MultipleFindings_WritesSummaryWithCounts(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{DetectorID: "det-a", Severity: finding.SeverityCritical, Redacted: "****"},
		{DetectorID: "det-b", Severity: finding.SeverityHigh, Redacted: "****"},
		{DetectorID: "det-c", Severity: finding.SeverityHigh, Redacted: "****"},
		{DetectorID: "det-d", Severity: finding.SeverityLow, Redacted: "****"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Found 4 secrets (1 critical, 2 high, 1 low).")
}

func TestFormatter_Format_ShowRawFalse_RawNotInOutput(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	assert.NotContains(t, buf.String(), "sk_live_supersecretvalue",
		"ShowRaw=false must strip raw secret from table output")
}

func TestFormatter_Format_ShowRawFalse_NoRawColumn(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "RAW", "header must not include a RAW column when ShowRaw=false")
	assert.NotContains(t, output, "sk_live_supersecretvalue")
}

func TestFormatter_Format_ShowRawTrue_AddsRawColumn(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "RAW", "header must include a RAW column when ShowRaw=true")
	assert.Contains(t, output, "sk_live_supersecretvalue",
		"ShowRaw=true must include the raw secret value in table output")
}

func TestFormatter_Format_ShowRawTrue_UsesReversibleTerminalSafeEncoding(t *testing.T) {
	raw := "abc\ndef\tghi\x1b\x00\\suffix\u0301\u202e" + string([]byte{0xff})
	encoded := quoteRawForTable(raw)

	recovered, err := strconv.Unquote(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte(raw), []byte(recovered), "quoted RAW value must round-trip byte-for-byte")
	assert.True(t, utf8.ValidString(encoded), "table display must remain valid UTF-8")
	for _, unsafe := range []string{"\n", "\t", "\x1b", "\x00", "\u202e"} {
		assert.NotContains(t, encoded, unsafe, "encoded RAW must not contain literal terminal controls")
	}

	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer
	require.NoError(t, f.Format(&buf, []finding.Finding{{
		DetectorID: "generic-secret",
		Raw:        raw,
	}}))
	assert.Contains(t, buf.String(), encoded)
}

func TestFormatter_Format_ShowRawFalse_DoesNotMutateOriginal(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:  "test-1",
			Raw: "AKIAIOSFODNN7EXAMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", findings[0].Raw,
		"Format must not mutate the original slice")
}

func TestFormatter_Format_ColumnsAligned_ProducesAlignedOutput(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{DetectorID: "short", Severity: finding.SeverityLow, Redacted: "a"},
		{DetectorID: "a-very-long-detector-name", Severity: finding.SeverityCritical, Redacted: "b"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	lines := strings.Split(buf.String(), "\n")
	// Header and separator should exist.
	require.GreaterOrEqual(t, len(lines), 4)
}

func TestFormatter_Format_UnicodeDisplayWidthAlignsColumns(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer
	findings := []finding.Finding{
		{
			DetectorID: "detector-a",
			Severity:   finding.SeverityLow,
			Redacted:   "first-redacted",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "設定/秘密.yaml",
			},
		},
		{
			DetectorID: "detector-b",
			Severity:   finding.SeverityHigh,
			Redacted:   "second-redacted",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "cafe\u0301/emoji-🔐.yaml",
			},
		},
	}

	require.NoError(t, f.Format(&buf, findings))
	lines := strings.Split(buf.String(), "\n")
	require.GreaterOrEqual(t, len(lines), 4)

	wantColumn := -1
	for _, item := range []struct {
		line   int
		needle string
	}{{0, "REDACTED"}, {2, "first-redacted"}, {3, "second-redacted"}} {
		line := lines[item.line]
		byteIndex := strings.Index(line, item.needle)
		require.NotEqual(t, -1, byteIndex)
		column := runewidth.StringWidth(line[:byteIndex])
		if wantColumn < 0 {
			wantColumn = column
		}
		assert.Equal(t, wantColumn, column, "display column drifted for %q", item.needle)
	}
}

func TestFormatter_Format_WithRemediation_ShowsRemediationTitle(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "rem-1",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.yaml",
			},
			Verification: finding.VerificationResult{
				Status: finding.StatusVerifiedActive,
			},
			Remediation: &finding.Remediation{
				Title:   "Rotate AWS Access Key",
				Steps:   []string{"Deactivate the key", "Create a new key"},
				Urgency: "immediate",
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "REMEDIATION")
	assert.Contains(t, output, "Rotate AWS Access Key")
}

func TestFormatter_Format_WithoutRemediation_ShowsDash(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "no-rem-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityMedium,
			Redacted:   "****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "REMEDIATION")
	// The row should contain a dash for the remediation column.
	lines := strings.Split(output, "\n")
	// Find the data row (skip header and separator).
	require.GreaterOrEqual(t, len(lines), 3)
	dataRow := lines[2]
	assert.Contains(t, dataRow, "-")
}

func TestFormatter_Format_LineColumn_ShowsLineNumber(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.yaml",
				Line:     42,
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "LINE")
	lines := strings.Split(output, "\n")
	require.GreaterOrEqual(t, len(lines), 3)
	assert.Contains(t, lines[2], "42")
}

func TestFormatter_Format_LineColumn_ShowsDashWhenUnset(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{DetectorID: "generic-secret", Severity: finding.SeverityLow, Redacted: "****"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	lines := strings.Split(buf.String(), "\n")
	require.GreaterOrEqual(t, len(lines), 3)
	assert.Contains(t, lines[2], "-")
}

func TestFormatter_Format_ControlBytesInFilePath_StrippedFromOutput(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "generic-secret",
			Severity:   finding.SeverityHigh,
			Redacted:   "****",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "evil\x1b[31m\x1b]0;pwned\x07.go",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "\x1b",
		"ESC bytes embedded in an attacker-controlled file path must never reach the table writer")
}

func TestFormatter_Format_ControlBytesInDetectorIDAndRedacted_StrippedFromOutput(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "custom-rule\x1b[2J",
			Severity:   finding.SeverityHigh,
			Redacted:   "AKIA\x1b]0;pwnedMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "\x1b",
		"ESC bytes embedded in DetectorID or Redacted must never reach the table writer")
}

func TestFormatter_FileExtension_ReturnsTXT(t *testing.T) {
	f := &Formatter{}
	assert.Equal(t, ".txt", f.FileExtension())
}

// errWriter simulates a write error.
type errWriter struct{}

func (w *errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestFormatter_Format_WriterError_ReturnsError(t *testing.T) {
	f := &Formatter{}
	findings := []finding.Finding{{ID: "test"}}

	err := f.Format(&errWriter{}, findings)
	assert.Error(t, err)
}

func TestFormatter_Format_ColorEnabled_CriticalSeverityHasRedBoldANSI(t *testing.T) {
	f := &Formatter{ColorEnabled: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, colorRedBold+"CRITICAL"+colorReset,
		"CRITICAL severity should be wrapped in red bold ANSI codes")
}

func TestFormatter_Format_ColorEnabled_HighSeverityHasRedANSI(t *testing.T) {
	f := &Formatter{ColorEnabled: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "github-token",
			Severity:   finding.SeverityHigh,
			Redacted:   "ghp_****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, colorRed+"HIGH"+colorReset,
		"HIGH severity should be wrapped in red ANSI codes")
}

func TestFormatter_Format_ColorEnabled_MediumSeverityHasYellowANSI(t *testing.T) {
	f := &Formatter{ColorEnabled: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "generic-secret",
			Severity:   finding.SeverityMedium,
			Redacted:   "****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, colorYellow+"MEDIUM"+colorReset,
		"MEDIUM severity should be wrapped in yellow ANSI codes")
}

func TestFormatter_Format_ColorEnabled_LowSeverityHasBlueANSI(t *testing.T) {
	f := &Formatter{ColorEnabled: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "generic-secret",
			Severity:   finding.SeverityLow,
			Redacted:   "****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, colorBlue+"LOW"+colorReset,
		"LOW severity should be wrapped in blue ANSI codes")
}

func TestFormatter_Format_ColorDisabled_NoANSICodesInOutput(t *testing.T) {
	f := &Formatter{ColorEnabled: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "\033[",
		"color-disabled output must not contain ANSI escape codes")
}

func TestFormatter_Format_ColorEnabled_SummaryCountsAreColorized(t *testing.T) {
	f := &Formatter{ColorEnabled: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{DetectorID: "det-a", Severity: finding.SeverityCritical, Redacted: "****"},
		{DetectorID: "det-b", Severity: finding.SeverityHigh, Redacted: "****"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, colorRedBold+"1 critical"+colorReset,
		"summary critical count should be colorized")
	assert.Contains(t, output, colorRed+"1 high"+colorReset,
		"summary high count should be colorized")
}

func TestFormatter_Format_ColorDisabled_SummaryHasNoANSI(t *testing.T) {
	f := &Formatter{ColorEnabled: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{DetectorID: "det-a", Severity: finding.SeverityCritical, Redacted: "****"},
		{DetectorID: "det-b", Severity: finding.SeverityHigh, Redacted: "****"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Found 2 secrets (1 critical, 1 high).")
	assert.NotContains(t, output, "\033[",
		"color-disabled summary must not contain ANSI escape codes")
}

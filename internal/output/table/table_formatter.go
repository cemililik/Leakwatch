// Package table provides a human-readable table output formatter for terminal display.
package table

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/HodeTech/leakwatch/internal/output"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// ANSI color codes for terminal output.
const (
	colorReset   = "\033[0m"
	colorRedBold = "\033[1;31m"
	colorRed     = "\033[31m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
)

// Formatter outputs findings as a human-readable table for terminal display.
type Formatter struct {
	// ShowRaw, when true, appends a trailing RAW column holding the unredacted
	// secret value. When false, no RAW column is emitted at all.
	ShowRaw bool

	// ColorEnabled, when true, wraps severity text with ANSI color codes.
	// Should be enabled only when writing to a terminal, not to files.
	ColorEnabled bool
}

// Format writes findings as a formatted table to the given writer.
// Columns: SEVERITY | DETECTOR | FILE | LINE | REDACTED | STATUS | REMEDIATION
// When ShowRaw is true, a trailing RAW column is appended.
// A summary line is appended at the bottom.
//
// DetectorID, FilePath, and Redacted are attacker-influenced (a malicious
// file name or a permissive custom detector rule can embed arbitrary bytes)
// and are sanitized via output.SanitizeForDisplay before reaching this
// writer, which is a real terminal when the CLI is run interactively. This
// strips control/ANSI-escape bytes so a crafted finding cannot inject
// terminal escape sequences into the operator's session.
func (f *Formatter) Format(w io.Writer, findings []finding.Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Write header.
	header := "SEVERITY\tDETECTOR\tFILE\tLINE\tREDACTED\tSTATUS\tREMEDIATION"
	separator := "--------\t--------\t----\t----\t--------\t------\t-----------"
	if f.ShowRaw {
		header += "\tRAW"
		separator += "\t---"
	}
	if _, err := fmt.Fprintln(tw, header); err != nil {
		return fmt.Errorf("failed to write table header: %w", err)
	}

	// Write separator.
	if _, err := fmt.Fprintln(tw, separator); err != nil {
		return fmt.Errorf("failed to write table separator: %w", err)
	}

	// Write rows.
	for _, fd := range findings {
		remediation := "-"
		if fd.Remediation != nil && fd.Remediation.Title != "" {
			remediation = fd.Remediation.Title
		}

		sevText := strings.ToUpper(fd.Severity.String())
		if f.ColorEnabled {
			sevText = f.colorizeSeverity(fd.Severity, sevText)
		}

		lineNo := "-"
		if fd.SourceMetadata.Line > 0 {
			lineNo = strconv.Itoa(fd.SourceMetadata.Line)
		}

		line := fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%s\t%s\t%s",
			sevText,
			output.SanitizeForDisplay(fd.DetectorID),
			output.SanitizeForDisplay(fd.SourceMetadata.FilePath),
			lineNo,
			output.SanitizeForDisplay(fd.Redacted),
			fd.Verification.Status.String(),
			remediation,
		)
		if f.ShowRaw {
			line += "\t" + fd.Raw
		}
		if _, err := fmt.Fprintln(tw, line); err != nil {
			return fmt.Errorf("failed to write table row: %w", err)
		}
	}

	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush table output: %w", err)
	}

	// Write summary line.
	summary := f.buildSummary(findings)
	if _, err := fmt.Fprintln(w, ""); err != nil {
		return fmt.Errorf("failed to write table summary: %w", err)
	}
	if _, err := fmt.Fprintln(w, summary); err != nil {
		return fmt.Errorf("failed to write table summary: %w", err)
	}

	return nil
}

// colorizeSeverity wraps the severity text with the appropriate ANSI color code.
func (f *Formatter) colorizeSeverity(sev finding.Severity, text string) string {
	var color string
	switch sev {
	case finding.SeverityCritical:
		color = colorRedBold
	case finding.SeverityHigh:
		color = colorRed
	case finding.SeverityMedium:
		color = colorYellow
	case finding.SeverityLow:
		color = colorBlue
	default:
		return text
	}
	return color + text + colorReset
}

// buildSummary generates the summary line: "Found X secrets (Y critical, Z high, ...)"
// When ColorEnabled is true, the severity counts are colorized.
func (f *Formatter) buildSummary(findings []finding.Finding) string {
	counts := map[finding.Severity]int{}
	for _, fd := range findings {
		counts[fd.Severity]++
	}

	total := len(findings)
	if total == 0 {
		return "Found 0 secrets."
	}

	var parts []string
	// Order: critical, high, medium, low.
	for _, sev := range []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
	} {
		if c, ok := counts[sev]; ok && c > 0 {
			part := fmt.Sprintf("%d %s", c, sev.String())
			if f.ColorEnabled {
				part = f.colorizeSeverity(sev, part)
			}
			parts = append(parts, part)
		}
	}

	return fmt.Sprintf("Found %d secrets (%s).", total, strings.Join(parts, ", "))
}

// FileExtension returns the text file extension.
func (f *Formatter) FileExtension() string {
	return ".txt"
}

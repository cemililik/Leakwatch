// Package table provides a human-readable table output formatter for terminal display.
package table

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/mattn/go-runewidth"

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
	headers := []string{"SEVERITY", "DETECTOR", "FILE", "LINE", "REDACTED", "STATUS", "REMEDIATION"}
	if f.ShowRaw {
		headers = append(headers, "RAW")
	}

	rows := make([]tableRow, 0, len(findings))
	for _, fd := range findings {
		remediation := "-"
		if fd.Remediation != nil && fd.Remediation.Title != "" {
			remediation = fd.Remediation.Title
		}

		plainSeverity := strings.ToUpper(fd.Severity.String())
		sevText := plainSeverity
		if f.ColorEnabled {
			sevText = f.colorizeSeverity(fd.Severity, sevText)
		}

		lineNo := "-"
		if fd.SourceMetadata.Line > 0 {
			lineNo = strconv.Itoa(fd.SourceMetadata.Line)
		}

		cells := []tableCell{
			{text: sevText, widthText: plainSeverity},
			{text: output.SanitizeForDisplay(fd.DetectorID)},
			{text: output.SanitizeForDisplay(fd.SourceMetadata.FilePath)},
			{text: lineNo},
			{text: output.SanitizeForDisplay(fd.Redacted)},
			{text: fd.Verification.Status.String()},
			{text: output.SanitizeForDisplay(remediation)},
		}
		if f.ShowRaw {
			cells = append(cells, tableCell{text: output.SanitizeForDisplay(fd.Raw)})
		}
		rows = append(rows, tableRow{cells: cells})
	}

	if err := writeDisplayWidthTable(w, headers, rows); err != nil {
		return err
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

const columnPadding = 2

type tableCell struct {
	text      string
	widthText string
}

func (c tableCell) displayWidth() int {
	if c.widthText != "" {
		return runewidth.StringWidth(c.widthText)
	}
	return runewidth.StringWidth(c.text)
}

type tableRow struct {
	cells []tableCell
}

// writeDisplayWidthTable aligns columns by terminal cells, not bytes or rune
// count. This keeps CJK, emoji, and combining-character paths aligned while
// allowing ANSI-colored severity text to use its uncolored widthText.
func writeDisplayWidthTable(w io.Writer, headers []string, rows []tableRow) error {
	widths := make([]int, len(headers))
	for index, header := range headers {
		widths[index] = runewidth.StringWidth(header)
	}
	for _, row := range rows {
		for index, cell := range row.cells {
			if index < len(widths) && cell.displayWidth() > widths[index] {
				widths[index] = cell.displayWidth()
			}
		}
	}

	headerCells := make([]tableCell, len(headers))
	separatorCells := make([]tableCell, len(headers))
	for index, header := range headers {
		headerCells[index] = tableCell{text: header}
		separatorCells[index] = tableCell{text: strings.Repeat("-", widths[index])}
	}
	if err := writeTableRow(w, tableRow{cells: headerCells}, widths); err != nil {
		return fmt.Errorf("failed to write table header: %w", err)
	}
	if err := writeTableRow(w, tableRow{cells: separatorCells}, widths); err != nil {
		return fmt.Errorf("failed to write table separator: %w", err)
	}
	for _, row := range rows {
		if err := writeTableRow(w, row, widths); err != nil {
			return fmt.Errorf("failed to write table row: %w", err)
		}
	}
	return nil
}

func writeTableRow(w io.Writer, row tableRow, widths []int) error {
	for index, cell := range row.cells {
		if index > 0 {
			if _, err := io.WriteString(w, strings.Repeat(" ", columnPadding)); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, cell.text); err != nil {
			return err
		}
		if index < len(row.cells)-1 {
			padding := widths[index] - cell.displayWidth()
			if padding > 0 {
				if _, err := io.WriteString(w, strings.Repeat(" ", padding)); err != nil {
					return err
				}
			}
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
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

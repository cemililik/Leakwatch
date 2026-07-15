// Package csv provides a CSV output formatter for Leakwatch findings.
package csv

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Formatter outputs findings in CSV format.
type Formatter struct {
	// ShowRaw, when true, appends a trailing "raw" column holding the
	// unredacted secret value. When false, no raw column is emitted at all.
	ShowRaw bool
}

// Format writes findings as CSV to the given writer.
// Header (ShowRaw=false): id,detector_id,severity,redacted,source,file_path,line,commit,verification_status,remediation
// Header (ShowRaw=true):  the above, with a trailing "raw" column.
// Every cell is sanitized against spreadsheet formula injection before writing.
func (f *Formatter) Format(w io.Writer, findings []finding.Finding) error {
	writer := csv.NewWriter(w)

	// Write header row.
	header := []string{"id", "detector_id", "severity", "redacted", "source", "file_path", "line", "commit", "verification_status", "remediation"}
	if f.ShowRaw {
		header = append(header, "raw")
	}
	if err := writer.Write(sanitizeRow(header)); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write one row per finding.
	for _, fd := range findings {
		remediation := ""
		if fd.Remediation != nil {
			remediation = fd.Remediation.Title
		}

		line := ""
		if fd.SourceMetadata.Line > 0 {
			line = strconv.Itoa(fd.SourceMetadata.Line)
		}

		row := []string{
			fd.ID,
			fd.DetectorID,
			fd.Severity.String(),
			fd.Redacted,
			sourceLabel(fd.SourceMetadata),
			fd.SourceMetadata.FilePath,
			line,
			fd.SourceMetadata.Commit,
			fd.Verification.Status.String(),
			remediation,
		}
		if f.ShowRaw {
			row = append(row, fd.Raw)
		}
		if err := writer.Write(sanitizeRow(row)); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV output: %w", err)
	}
	return nil
}

// sourceLabel returns a human-readable label identifying the repository,
// container image, or Slack channel a finding originated from, so multi-repo
// scans (which combine findings from several git repositories into one CSV,
// see cmd/scan_repos.go) and non-git sources remain attributable without
// cross-referencing JSON. It returns the first populated field, in priority
// order: git repository, container image, Slack channel name (falling back
// to the channel ID). Returns "" when the source carries none of these
// (e.g. a plain filesystem scan of a single directory).
func sourceLabel(m finding.SourceMetadata) string {
	switch {
	case m.Repository != "":
		return m.Repository
	case m.Image != "":
		return m.Image
	case m.ChannelName != "":
		return m.ChannelName
	case m.Channel != "":
		return m.Channel
	default:
		return ""
	}
}

// formulaInjectionPrefixes are the leading characters a spreadsheet may treat as
// the start of a formula or command when a CSV cell is opened. Attacker-influenced
// fields (custom-rule IDs, redacted values, remediation titles) could otherwise
// trigger execution, so any cell beginning with one of these is neutralized.
const formulaInjectionPrefixes = "=+-@\t\r"

// sanitizeCell neutralizes spreadsheet formula injection by prefixing a single
// quote to any value beginning with a formula-trigger character. The single
// quote tells common spreadsheet applications to treat the cell as literal text.
func sanitizeCell(value string) string {
	if value == "" {
		return value
	}
	if strings.ContainsRune(formulaInjectionPrefixes, rune(value[0])) {
		return "'" + value
	}
	return value
}

// sanitizeRow applies sanitizeCell to every cell in a row in place and returns it.
func sanitizeRow(row []string) []string {
	for i, cell := range row {
		row[i] = sanitizeCell(cell)
	}
	return row
}

// FileExtension returns the CSV file extension.
func (f *Formatter) FileExtension() string {
	return ".csv"
}

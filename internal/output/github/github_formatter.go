// Package github provides an output formatter that emits GitHub Actions
// workflow commands (::error / ::warning / ::notice) so Leakwatch findings show
// up as inline annotations on pull requests and in the workflow run log.
//
// The format is meant to be written to the Actions runner's stdout: workflow
// commands are only interpreted on the live command stream, so writing them to a
// file has no effect. For safety, this formatter NEVER emits the raw secret
// value — annotations render in the (often public) PR UI and run logs, so only
// the redacted value is shown regardless of any --show-raw setting.
//
// Reference: https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
package github

import (
	"fmt"
	"io"
	"strings"

	"github.com/HodeTech/leakwatch/internal/output"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Formatter emits findings as GitHub Actions workflow commands.
type Formatter struct{}

// Format writes one workflow command per finding to w. A finding with a known
// file path is anchored to that file and line so GitHub renders it inline on the
// "Files changed" view; a finding without a file path becomes a run-level
// annotation (no file/line properties).
func (f *Formatter) Format(w io.Writer, findings []finding.Finding) error {
	var b strings.Builder
	for i := range findings {
		writeCommand(&b, findings[i])
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("failed to write GitHub annotations: %w", err)
	}
	return nil
}

// FileExtension returns the file extension for this format. Workflow commands
// are intended for stdout, not a file; ".txt" is returned to satisfy the
// Formatter contract.
func (f *Formatter) FileExtension() string {
	return ".txt"
}

// writeCommand appends a single workflow command for fd to b.
func writeCommand(b *strings.Builder, fd finding.Finding) {
	props := make([]string, 0, 3)
	if path := fd.SourceMetadata.FilePath; path != "" {
		props = append(props, "file="+escapeProperty(path))
		if fd.SourceMetadata.Line > 0 {
			props = append(props, fmt.Sprintf("line=%d", fd.SourceMetadata.Line))
		}
	}
	props = append(props, "title="+escapeProperty(annotationTitle(fd)))

	b.WriteString("::")
	b.WriteString(annotationLevel(fd))
	b.WriteByte(' ')
	b.WriteString(strings.Join(props, ","))
	b.WriteString("::")
	b.WriteString(escapeData(annotationMessage(fd)))
	b.WriteByte('\n')
}

// annotationLevel decides the GitHub annotation level for a finding. A secret
// confirmed live by verification is an incident and is always emitted as an
// error, regardless of its nominal severity; otherwise severity decides.
func annotationLevel(fd finding.Finding) string {
	if fd.Verification.Status == finding.StatusVerifiedActive {
		return "error"
	}
	return severityToLevel(fd.Severity)
}

// severityToLevel maps a finding severity to a GitHub annotation level. GitHub
// supports only error/warning/notice, so medium and low both map to "notice".
func severityToLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "error"
	case finding.SeverityHigh:
		return "warning"
	case finding.SeverityMedium, finding.SeverityLow:
		return "notice"
	default:
		return "notice"
	}
}

// annotationTitle is the bold heading GitHub shows above the annotation.
func annotationTitle(fd finding.Finding) string {
	return "Leakwatch: " + fd.DetectorID
}

// annotationMessage is the annotation body. It uses only the redacted value and
// appends the verification verdict so an active key is visibly an incident.
func annotationMessage(fd finding.Finding) string {
	var sb strings.Builder
	sb.WriteString("Potential secret detected by ")
	sb.WriteString(fd.DetectorID)
	sb.WriteString(" (")
	sb.WriteString(fd.Severity.String())
	sb.WriteByte(')')
	if fd.Redacted != "" {
		sb.WriteString(": ")
		sb.WriteString(fd.Redacted)
	}
	switch fd.Verification.Status {
	case finding.StatusVerifiedActive:
		sb.WriteString(" — verified ACTIVE; rotate this credential immediately")
	case finding.StatusVerifiedInactive:
		sb.WriteString(" — verified inactive")
	case finding.StatusUnverified, finding.StatusVerifyError:
		// No suffix: status is unknown, so don't imply a verdict.
	}
	return sb.String()
}

// escapeData escapes a workflow command's message payload. Percent is replaced
// first so the escape sequences introduced below are not double-escaped.
//
// After the workflow-command metacharacters are encoded, output.SanitizeForDisplay
// strips any remaining control bytes — most importantly ESC (0x1B), which
// begins ANSI/OSC/DCS terminal escape sequences and is not one of the
// characters GitHub's own workflow-command syntax requires escaping. This
// stream is rendered in the Actions run log, a terminal-like view, so a
// malicious file name or a permissive custom detector rule must not be able
// to inject raw escape sequences into it. \r and \n are already percent-encoded
// above (to %0D/%0A) before this runs, so this sanitization pass only ever
// strips bytes that survived unescaped, such as ESC.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return output.SanitizeForDisplay(s)
}

// escapeProperty escapes a workflow command property value. In addition to the
// message escapes, "," and ":" are encoded because they delimit properties.
// See escapeData's doc comment for why output.SanitizeForDisplay is applied
// last.
func escapeProperty(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return output.SanitizeForDisplay(s)
}

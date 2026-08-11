// Package output defines output formatter interfaces and shared helpers used
// across the concrete formatters (json, sarif, csv, table, github).
package output

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Formatter outputs findings in a specific format.
type Formatter interface {
	// Format writes findings to the given writer.
	Format(w io.Writer, findings []finding.Finding) error

	// FileExtension returns the file extension for this format (including the
	// leading dot, e.g. ".sarif").
	//
	// The cmd/ output layer uses it to auto-suffix a bare --output path that
	// has no extension, so `--format sarif --output results` writes
	// results.sarif. A path that already carries an extension is left
	// untouched.
	FileExtension() string
}

// SanitizeForDisplay strips Unicode control characters — including the ESC
// (0x1B) byte that begins ANSI/OSC/DCS escape sequences, and the C0/C1
// control ranges more generally — from s. Unicode bidi controls are rendered
// as visible \\uXXXX escapes so they cannot reorder terminal text while their
// presence and exact code point remain available to the operator.
//
// Apply this to any attacker-influenced field (file path, detector ID,
// redacted match value, ...) before it is written somewhere an operator
// views directly: a real terminal (table formatter) or a stream consumed by
// another tool that itself renders to a terminal (e.g. GitHub Actions'
// workflow-command log). Without it, a maliciously named file (Git/most
// filesystems permit any byte except '/' and NUL) or a permissive
// custom-rule match can inject cursor moves, color changes, title-bar
// writes, or other terminal escape sequences into the operator's session.
//
// Control bytes are removed rather than substituted: the safe behavior for a
// terminal-facing display field is to drop them entirely rather than risk
// re-introducing structure (e.g. a substitute delimiter) that could itself be
// misinterpreted downstream. Bidi controls are escaped instead because their
// code-point identity is useful evidence and the visible ASCII form is inert.
//
// Do NOT apply this to the unredacted secret value (Raw) shown under
// --show-raw: that field's entire purpose is exact fidelity to the actual
// secret, and silently dropping bytes from it would misrepresent the secret
// being reported.
func SanitizeForDisplay(s string) string {
	var sanitized strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if isBidiControl(r) {
			_, _ = fmt.Fprintf(&sanitized, "\\u%04X", r)
			continue
		}
		sanitized.WriteRune(r)
	}
	return sanitized.String()
}

// isBidiControl covers the Unicode bidi controls that can alter the visual
// order of surrounding text. Other format characters, including emoji ZWJ,
// remain intact so ordinary internationalized paths are not degraded.
func isBidiControl(r rune) bool {
	return r == '\u061C' ||
		r == '\u200E' ||
		r == '\u200F' ||
		(r >= '\u202A' && r <= '\u202E') ||
		(r >= '\u2066' && r <= '\u2069')
}

// Package output defines output formatter interfaces and shared helpers used
// across the concrete formatters (json, sarif, csv, table, github).
package output

import (
	"io"
	"strings"
	"unicode"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Formatter outputs findings in a specific format.
type Formatter interface {
	// Format writes findings to the given writer.
	Format(w io.Writer, findings []finding.Finding) error

	// FileExtension returns the file extension for this format.
	//
	// NOTE: as of this writing, no cmd/ caller consumes FileExtension() to
	// auto-suffix a bare --output filename without an extension; wiring that
	// up (or removing the method if it never gains a caller) is deferred to a
	// later wave. It remains part of the interface, implemented by every
	// formatter, so a future caller can rely on it without a breaking change.
	FileExtension() string
}

// SanitizeForDisplay strips Unicode control characters — including the ESC
// (0x1B) byte that begins ANSI/OSC/DCS escape sequences, and the C0/C1
// control ranges more generally — from s.
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
// Bytes are removed rather than substituted: the safe behavior for a
// terminal-facing display field is to drop the disallowed byte entirely
// rather than risk re-introducing structure (e.g. a substitute delimiter)
// that could itself be misinterpreted downstream.
//
// Do NOT apply this to the unredacted secret value (Raw) shown under
// --show-raw: that field's entire purpose is exact fidelity to the actual
// secret, and silently dropping bytes from it would misrepresent the secret
// being reported.
func SanitizeForDisplay(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// Package gcp provides a GCP Service Account Key secret detector.
package gcp

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	gcpServiceAccountPattern = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	privateKeyIDPattern      = regexp.MustCompile(`"private_key_id"\s*:\s*"([^"]+)"`)
	clientEmailPattern       = regexp.MustCompile(`"client_email"\s*:\s*"([^"]+)"`)
	// privateKeyValuePattern matches the private_key field together with its
	// value so the PEM body can be replaced before it is ever stored.
	privateKeyValuePattern = regexp.MustCompile(`("private_key"\s*:\s*")(?:\\.|[^"\\])*(")`)
)

// privateKeyRedaction is the placeholder that replaces any private_key PEM body
// found inside a service account block. The PEM body itself is never retained.
const privateKeyRedaction = `${1}[REDACTED]${2}`

// Detector detects GCP Service Account Key files.
type Detector struct{}

// ID returns the unique identifier of the GCP Service Account detector.
func (d *Detector) ID() string { return "gcp-service-account" }

// Description returns a human-readable description of the GCP Service Account detector.
func (d *Detector) Description() string { return "GCP Service Account Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for GCP Service Account detection.
func (d *Detector) Keywords() []string {
	return []string{"service_account", "private_key_id", "client_email"}
}

// Severity returns the default severity level for GCP Service Account findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for GCP Service Account Key JSON markers. Each
// service_account block is scoped to its own enclosing JSON object so that a
// file containing multiple accounts yields one finding per account, each
// carrying its own private_key_id and client_email. The private_key PEM body is
// never placed in Raw, RawV2, or Redacted; only the private_key_id and
// client_email identify the secret, both redacted.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := gcpServiceAccountPattern.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return nil
	}

	// Computed once per Scan call (not per marker) so brace-scoping for every
	// marker in this input shares the same quoted-string map instead of
	// recomputing it per match.
	quoted := quotedSpans(data)

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, loc := range matches {
		// Scope extraction to the JSON object that encloses this marker so each
		// account contributes its own fields rather than the first account's.
		block := enclosingObject(data, quoted, loc[0], loc[1])

		raw := extractSubmatch(privateKeyIDPattern, block)
		email := extractSubmatch(clientEmailPattern, block)

		redacted := "GCP Service Account Key ****"
		if len(email) > 0 {
			redacted = "****@*.iam.gserviceaccount.com"
		}

		extra := make(map[string]string)
		if len(email) > 0 {
			extra["client_email"] = string(email)
		}
		if len(raw) > 0 {
			extra["private_key_id"] = string(raw)
		}

		f := detector.RawFinding{
			DetectorID: d.ID(),
			// raw is a subslice of block (itself a subslice of data); clone it so
			// the finding does not alias (and pin in memory) the scanned chunk
			// buffer.
			Raw: bytes.Clone(raw),
			// RawV2 holds only this account's block with the private_key body
			// stripped, never the whole file and never the PEM material.
			// redactPrivateKey already returns a freshly allocated slice
			// (regexp.ReplaceAll never aliases its input), so no separate clone
			// is needed here.
			RawV2:     redactPrivateKey(block),
			Redacted:  redacted,
			ExtraData: extra,
		}
		if len(raw) == 0 {
			f.Raw = []byte("service_account")
		}

		findings = append(findings, f)
	}
	return findings
}

// enclosingObject returns the smallest brace-balanced JSON object that contains
// the byte range [start,end). If no balanced object can be determined it falls
// back to the marker range itself, ensuring a non-nil, account-local slice that
// never spans the whole input. quoted marks which byte offsets in data lie
// inside a JSON string literal (see quotedSpans) so that a literal '{' or '}'
// inside a string value (e.g. a free-text "description" field) is never
// mistaken for a structural brace.
func enclosingObject(data []byte, quoted []bool, start, end int) []byte {
	open := findEnclosingOpenBrace(data, quoted, start)
	if open == -1 {
		return data[start:end]
	}
	if closeIdx := findMatchingCloseBrace(data, quoted, open); closeIdx != -1 {
		return data[open : closeIdx+1]
	}
	// Unbalanced (truncated) input: return from the opening brace to the end.
	return data[open:]
}

// findEnclosingOpenBrace walks backwards from start to the opening brace whose
// matching close brace would contain the marker, accounting for nested objects.
// Braces at a quoted[i] offset (inside a JSON string value) are ignored rather
// than counted, since they are not structural JSON syntax. It returns the
// index of the brace, or -1 if none is found.
func findEnclosingOpenBrace(data []byte, quoted []bool, start int) int {
	depth := 0
	for i := start; i >= 0; i-- {
		if quoted[i] {
			continue
		}
		switch data[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// findMatchingCloseBrace walks forwards from the opening brace at open to its
// matching close brace, accounting for nested objects. Braces at a quoted[i]
// offset (inside a JSON string value) are ignored rather than counted. It
// returns the index of that brace, or -1 if the input is unbalanced (truncated).
func findMatchingCloseBrace(data []byte, quoted []bool, open int) int {
	depth := 0
	for i := open; i < len(data); i++ {
		if quoted[i] {
			continue
		}
		switch data[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// quotedSpans returns, for each byte offset in data, whether that offset lies
// strictly inside an unescaped JSON string literal (between an opening and
// closing double quote, exclusive of the quotes themselves). It performs a
// single linear pass tracking quote and backslash-escape state, so
// findEnclosingOpenBrace/findMatchingCloseBrace can ignore '{'/'}' characters
// that appear inside string values (for example a free-text "description"
// field) instead of mistaking them for structural JSON braces. This is a
// best-effort lexical scan, not a full JSON parser: it is only asked to
// distinguish string-literal bytes from structural bytes, which is all
// brace-depth counting needs.
func quotedSpans(data []byte) []bool {
	quoted := make([]bool, len(data))
	inString := false
	escaped := false
	for i, b := range data {
		if inString {
			quoted[i] = true
		}
		if escaped {
			escaped = false
			continue
		}
		switch b {
		case '\\':
			if inString {
				escaped = true
			}
		case '"':
			inString = !inString
		}
	}
	return quoted
}

// redactPrivateKey returns a copy of block with any private_key PEM value
// replaced by a placeholder. The original PEM body is never copied into the
// result.
func redactPrivateKey(block []byte) []byte {
	return privateKeyValuePattern.ReplaceAll(block, []byte(privateKeyRedaction))
}

// extractSubmatch returns the first capture group from the given pattern, or nil.
func extractSubmatch(pattern *regexp.Regexp, data []byte) []byte {
	groups := pattern.FindSubmatch(data)
	if len(groups) < 2 {
		return nil
	}
	return groups[1]
}

func init() {
	detector.Register(&Detector{})
}

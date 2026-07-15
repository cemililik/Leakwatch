// Package openai provides an OpenAI API Key secret detector.
package openai

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// openAIKeyPattern covers the three OpenAI secret-key shapes in use today.
// Alternatives are ordered most-specific-first: Go's regexp package uses
// leftmost-first (not leftmost-longest) alternation semantics, so a project
// key or service-account key is always claimed by its specific branch before
// the generic legacy branch below it gets a chance to under-match a prefix of
// it.
//
//  1. sk-proj-  — project-scoped keys (the current default format).
//  2. sk-svcacct- — service-account keys.
//  3. sk-       — legacy keys that predate project scoping. This branch is
//     intentionally broad (no fixed marker beyond the shared "sk-" prefix
//     exists for this format), closing the tracked roadmap gap (see
//     docs/05-ROADMAP.md "Broaden OpenAI key coverage" and review section
//     04-detectors-d3.md HIGH finding "openai_key.go:12").
var openAIKeyPattern = regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{50,}|sk-svcacct-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}`)

// Detector detects OpenAI API Keys.
type Detector struct{}

func (d *Detector) ID() string { return "openai-api-key" }

func (d *Detector) Description() string { return "OpenAI API Key" }

// Keywords intentionally includes the bare "sk-" prefix, not just
// "sk-proj-"/"sk-svcacct-": the legacy key format has no fixed marker beyond
// "sk-", so restricting Keywords() to the two specific prefixes would let the
// Aho-Corasick matcher gate legacy keys out before Scan ever runs on them —
// exactly the keyword/regex misalignment bug class (DETB-M-01) the project
// has already hit once. See review section 19-test-quality.md.
func (d *Detector) Keywords() []string { return []string{"sk-proj-", "sk-svcacct-", "sk-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for OpenAI API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := openAIKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			// Clone so Raw does not keep the whole scanned chunk buffer alive
			// for the rest of the scan (see review section 04-detectors-d3.md
			// MED finding on Raw aliasing; mirrors mailgun/okta precedent).
			Raw:      bytes.Clone(match),
			Redacted: detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

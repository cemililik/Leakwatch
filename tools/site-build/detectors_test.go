package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestGoToJSRegex(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantSrc   string
		wantFlags string
		wantOK    bool
	}{
		{
			name:      "no flags",
			pattern:   `sk-[a-zA-Z0-9]{20,}`,
			wantSrc:   `sk-[a-zA-Z0-9]{20,}`,
			wantFlags: "",
			wantOK:    true,
		},
		{
			name:      "case-insensitive flag lifted",
			pattern:   `(?i)okta`,
			wantSrc:   `okta`,
			wantFlags: "i",
			wantOK:    true,
		},
		{
			name:      "multiple leading flags",
			pattern:   `(?im)^secret`,
			wantSrc:   `^secret`,
			wantFlags: "im",
			wantOK:    true,
		},
		{
			name:    "ungreedy flag is rejected, not silently dropped",
			pattern: `(?U)a+`,
			wantOK:  false,
		},
		{
			name:    "ungreedy flag combined with others is still rejected",
			pattern: `(?iU)a+`,
			wantOK:  false,
		},
		{
			name:    "unicode property class is rejected",
			pattern: `\p{L}+`,
			wantOK:  false,
		},
		{
			name:    "negated unicode property class is rejected",
			pattern: `\P{L}+`,
			wantOK:  false,
		},
		{
			name:    "backreference to named group is rejected",
			pattern: `(?P<x>a)(?P=x)`,
			wantOK:  false,
		},
		{
			name:      "named group syntax is converted",
			pattern:   `(?P<name>[a-z]+)`,
			wantSrc:   `(?<name>[a-z]+)`,
			wantFlags: "",
			wantOK:    true,
		},
		{
			name:      "go anchors are converted",
			pattern:   `\Afoo\z`,
			wantSrc:   `^foo$`,
			wantFlags: "",
			wantOK:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, flags, ok := goToJSRegex(tt.pattern)
			if ok != tt.wantOK {
				t.Fatalf("goToJSRegex(%q) ok = %v, want %v", tt.pattern, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if src != tt.wantSrc || flags != tt.wantFlags {
				t.Errorf("goToJSRegex(%q) = (%q, %q), want (%q, %q)", tt.pattern, src, flags, tt.wantSrc, tt.wantFlags)
			}
		})
	}
}

// parseSnippet parses a minimal Go source string into an *ast.File for use by
// extractDetectors in tests.
func parseSnippet(t *testing.T, src string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "detector.go", src, 0)
	if err != nil {
		t.Fatalf("parse snippet: %v", err)
	}
	return f
}

func TestExtractDetectors_UnconditionalSinglePattern(t *testing.T) {
	src := `
package example

import "regexp"

var tokenPattern = regexp.MustCompile(` + "`sk-[a-zA-Z0-9]{20,}`" + `)

type Detector struct{}

func (d *Detector) ID() string { return "example-token" }
func (d *Detector) Keywords() []string { return []string{"sk-"} }

func (d *Detector) Scan(data []byte) {
	matches := tokenPattern.FindAll(data, -1)
	_ = matches
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(dropped) != 0 {
		t.Fatalf("unexpected drops: %v", dropped)
	}
	if len(out) != 1 || out[0].ID != "example-token" {
		t.Fatalf("unexpected entries: %+v", out)
	}
	if len(out[0].Patterns) != 1 || out[0].Patterns[0].Src != `sk-[a-zA-Z0-9]{20,}` {
		t.Fatalf("unexpected patterns: %+v", out[0].Patterns)
	}
}

// TestExtractDetectors_GateAndExtractionOnlyExcluded mirrors the real
// gcp-service-account shape: a trigger pattern used with FindAllIndex, plus
// patterns referenced only as call arguments for metadata extraction. Only
// the trigger should be emitted (regression test for the AND-to-OR
// conversion bug in review section 28).
func TestExtractDetectors_GateAndExtractionOnlyExcluded(t *testing.T) {
	src := `
package example

import "regexp"

var (
	triggerPattern = regexp.MustCompile(` + "`\"type\":\"service_account\"`" + `)
	metaPattern     = regexp.MustCompile(` + "`\"email\":\"([^\"]+)\"`" + `)
)

type Detector struct{}

func (d *Detector) ID() string { return "example-gcp" }
func (d *Detector) Keywords() []string { return []string{"service_account"} }

func (d *Detector) Scan(data []byte) {
	matches := triggerPattern.FindAllIndex(data, -1)
	for _, loc := range matches {
		_ = extractSubmatch(metaPattern, data[loc[0]:loc[1]])
	}
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(dropped) != 0 {
		t.Fatalf("unexpected drops: %v", dropped)
	}
	if len(out) != 1 {
		t.Fatalf("unexpected entries: %+v", out)
	}
	if len(out[0].Patterns) != 1 || out[0].Patterns[0].Src != `"type":"service_account"` {
		t.Fatalf("metaPattern must not be emitted as an independent OR'd trigger, got: %+v", out[0].Patterns)
	}
}

// TestExtractDetectors_MatchGateExcluded mirrors okta/mailgun: a context
// pattern used only via .Match() in a guard clause must never be emitted as
// an independent trigger, even though the real trigger pattern that follows
// the guard clause still must be.
func TestExtractDetectors_MatchGateExcluded(t *testing.T) {
	src := `
package example

import "regexp"

var (
	contextPattern = regexp.MustCompile(` + "`(?i)okta`" + `)
	tokenPattern    = regexp.MustCompile(` + "`00[A-Za-z0-9_-]{40}`" + `)
)

type Detector struct{}

func (d *Detector) ID() string { return "example-okta" }
func (d *Detector) Keywords() []string { return []string{"okta"} }

func (d *Detector) Scan(data []byte) {
	if !contextPattern.Match(data) {
		return
	}
	matches := tokenPattern.FindAll(data, -1)
	_ = matches
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(dropped) != 0 {
		t.Fatalf("unexpected drops: %v", dropped)
	}
	if len(out) != 1 {
		t.Fatalf("unexpected entries: %+v", out)
	}
	if len(out[0].Patterns) != 1 || out[0].Patterns[0].Src != `00[A-Za-z0-9_-]{40}` {
		t.Fatalf("contextPattern must not be emitted as an independent OR'd trigger, got: %+v", out[0].Patterns)
	}
}

// TestExtractDetectors_ConditionalTriggerExcluded mirrors notion-token: a
// second pattern whose FindAll call itself lives inside the body of an `if`
// (gated by a helper function call, not by referencing the pattern var) must
// not be emitted as an unconditional OR'd trigger.
func TestExtractDetectors_ConditionalTriggerExcluded(t *testing.T) {
	src := `
package example

import "regexp"

var (
	unconditionalPattern = regexp.MustCompile(` + "`ntn_[A-Za-z0-9]{43,}`" + `)
	conditionalPattern    = regexp.MustCompile(` + "`secret_[A-Za-z0-9]{43,}`" + `)
)

type Detector struct{}

func (d *Detector) ID() string { return "example-notion" }
func (d *Detector) Keywords() []string { return []string{"ntn_", "secret_"} }

func (d *Detector) Scan(data []byte) {
	for _, m := range unconditionalPattern.FindAll(data, -1) {
		_ = m
	}
	if hasContext(data) {
		for _, m := range conditionalPattern.FindAll(data, -1) {
			_ = m
		}
	}
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(dropped) != 0 {
		t.Fatalf("unexpected drops: %v", dropped)
	}
	if len(out) != 1 {
		t.Fatalf("unexpected entries: %+v", out)
	}
	if len(out[0].Patterns) != 1 || out[0].Patterns[0].Src != `ntn_[A-Za-z0-9]{43,}` {
		t.Fatalf("conditionalPattern must not be emitted as an unconditional OR'd trigger, got: %+v", out[0].Patterns)
	}
}

// TestExtractDetectors_AllReferencesGatedDropsDetectorWithWarning covers the
// case where every pattern reference found in Scan turns out to be a
// gate/extraction/conditional use — the detector type must be reported as
// dropped (for buildDetectors' warning/-strict check) rather than silently
// vanishing or falling back to unrelated file-level patterns.
func TestExtractDetectors_AllReferencesGatedDropsDetectorWithWarning(t *testing.T) {
	src := `
package example

import "regexp"

var gateOnlyPattern = regexp.MustCompile(` + "`x`" + `)

type Detector struct{}

func (d *Detector) ID() string { return "example-gate-only" }
func (d *Detector) Keywords() []string { return []string{"x"} }

func (d *Detector) Scan(data []byte) {
	if !gateOnlyPattern.Match(data) {
		return
	}
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(out) != 0 {
		t.Fatalf("expected no emitted entries, got: %+v", out)
	}
	if len(dropped) != 1 || dropped[0] != "example-gate-only" {
		t.Fatalf("expected example-gate-only to be reported as dropped, got: %v", dropped)
	}
}

// TestExtractDetectors_ConcatenatedStringPatternIsResolved is a regression
// test for dbconn's adonetPattern: a MustCompile call whose argument is a
// `+`-joined chain of string literals (common for laying out long patterns
// across lines) must resolve to the concatenated pattern, not be silently
// skipped as an unsupported expression.
func TestExtractDetectors_ConcatenatedStringPatternIsResolved(t *testing.T) {
	src := `
package example

import "regexp"

var multiLinePattern = regexp.MustCompile(
	` + "`foo`" + ` +
		` + "`bar`" + `,
)

type Detector struct{}

func (d *Detector) ID() string { return "example-concat" }
func (d *Detector) Keywords() []string { return []string{"foo"} }

func (d *Detector) Scan(data []byte) {
	matches := multiLinePattern.FindAll(data, -1)
	_ = matches
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(dropped) != 0 {
		t.Fatalf("unexpected drops: %v", dropped)
	}
	if len(out) != 1 || len(out[0].Patterns) != 1 || out[0].Patterns[0].Src != "foobar" {
		t.Fatalf("expected concatenated pattern %q, got: %+v", "foobar", out)
	}
}

// TestExtractDetectors_ConstIdentPatternSkippedNotMisresolved ensures a
// MustCompile call referencing a non-literal identifier (e.g. a const defined
// elsewhere) is cleanly skipped rather than mis-resolved into a wrong string.
func TestExtractDetectors_ConstIdentPatternSkippedNotMisresolved(t *testing.T) {
	src := `
package example

import "regexp"

const rawPattern = ` + "`foo`" + `

var identPattern = regexp.MustCompile(rawPattern)

type Detector struct{}

func (d *Detector) ID() string { return "example-const-ident" }
func (d *Detector) Keywords() []string { return []string{"foo"} }

func (d *Detector) Scan(data []byte) {
	matches := identPattern.FindAll(data, -1)
	_ = matches
}
`
	f := parseSnippet(t, src)
	out, dropped := extractDetectors(f)
	if len(out) != 0 {
		t.Fatalf("expected no emitted entries for an unresolvable const-ident pattern, got: %+v", out)
	}
	if len(dropped) != 1 || dropped[0] != "example-const-ident" {
		t.Fatalf("expected example-const-ident to be reported as dropped, got: %v", dropped)
	}
}

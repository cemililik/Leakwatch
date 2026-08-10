package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
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

func TestExtractDetectors_CorrelatedContractPreservesANDSemantics(t *testing.T) {
	src := `
package example

import (
	"regexp"
	"example/internal/detector"
)

const nearby = 128
var primary = regexp.MustCompile(` + "`SECRET=([^\\s]+)`" + `)
var companion = regexp.MustCompile(` + "`SID=(SK[0-9a-f]{32})`" + `)
var metadata = regexp.MustCompile(` + "`ACCOUNT=(AC[0-9a-f]{32})`" + `)

type Detector struct{}
func (*Detector) ID() string { return "correlated" }
func (*Detector) Scan(data []byte) {
	_ = primary.FindAllSubmatchIndex(data, -1)
	_ = companion.FindAllSubmatchIndex(data, -1)
	_ = metadata.FindAllSubmatchIndex(data, -1)
}
func (*Detector) PlaygroundPatternContract() detector.PlaygroundPatternContract {
	return detector.PlaygroundPatternContract{
		Primary: []*regexp.Regexp{primary},
		RequiredNearby: []*regexp.Regexp{companion},
		ProximityBytes: nearby,
		SameLogicalBlock: true,
		RejectPlaceholders: true,
		OneToOne: true,
	}
}
`
	out, dropped := extractDetectors(parseSnippet(t, src))
	if len(dropped) != 0 || len(out) != 1 {
		t.Fatalf("unexpected extraction result: out=%+v dropped=%v", out, dropped)
	}
	entry := out[0]
	if len(entry.Patterns) != 1 || entry.Patterns[0].Src != `SECRET=([^\s]+)` {
		t.Fatalf("primary patterns = %+v", entry.Patterns)
	}
	if entry.Correlation == nil || len(entry.Correlation.RequiredNearby) != 1 {
		t.Fatalf("correlation = %+v", entry.Correlation)
	}
	if entry.Correlation.RequiredNearby[0].Src != `SID=(SK[0-9a-f]{32})` ||
		entry.Correlation.ProximityBytes != 128 || !entry.Correlation.SameLogicalBlock || !entry.Correlation.RejectPlaceholders || !entry.Correlation.OneToOne {
		t.Fatalf("correlation = %+v", entry.Correlation)
	}
}

func TestPlayground_TwilioRequiresNearbySID(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required to verify browser detector contracts")
	}
	root, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	script := `
const fs = require("fs");
const vm = require("vm");
const elements = {};
function element() { return { value: "", textContent: "", innerHTML: "", addEventListener() {}, focus() {} }; }
global.window = { addEventListener() {} };
global.document = {
  getElementById(id) { return elements[id] || (elements[id] = element()); },
  querySelectorAll() { return []; },
  addEventListener() {}
};
global.navigator = {};
global.setTimeout = function () {};
vm.runInThisContext(fs.readFileSync(process.argv[1], "utf8"));
vm.runInThisContext(fs.readFileSync(process.argv[2], "utf8"));
const key = "SK" + "ab12cd34".repeat(4);
const account = "AC" + "ab12cd34".repeat(4);
const secret = "opaque/+Twilio.Secret==";
function count(input) { return window.LW_PLAYGROUND_DETECT(input).filter(f => f.id === "twilio-api-key").length; }
const cases = [
  ["bare key SID", "TWILIO_API_KEY_SID=" + key, 0],
  ["bare account SID", "TWILIO_ACCOUNT_SID=" + account, 0],
  ["unpaired secret", "TWILIO_API_KEY_SECRET=" + secret, 0],
  ["paired", "TWILIO_API_KEY_SID=" + key + "\nTWILIO_API_KEY_SECRET=" + secret, 1],
	  ["short opaque secret", "TWILIO_API_KEY_SID=" + key + "\nTWILIO_API_KEY_SECRET=x7-K", 1],
	  ["placeholder", "TWILIO_API_KEY_SID=" + key + "\nTWILIO_API_KEY_SECRET=your_api_key_secret", 0],
	  ["reference", "TWILIO_API_KEY_SID=" + key + "\nTWILIO_API_KEY_SECRET=${TWILIO_API_KEY_SECRET}", 0],
	  ["one SID is not reused", "TWILIO_API_KEY_SID=" + key + "\nTWILIO_API_KEY_SECRET=" + secret + "\nTWILIO_API_KEY_SECRET=second-opaque-secret", 1],
	  ["escaped quote is not truncated", "TWILIO_API_KEY_SID=" + key + "\nTWILIO_API_KEY_SECRET=\"opaque\\\"tail\"", 0],
  ["different block", "TWILIO_API_KEY_SID=" + key + "\n\nTWILIO_API_KEY_SECRET=" + secret, 0]
];
for (const [name, input, want] of cases) {
  const got = count(input);
  if (got !== want) throw new Error(name + ": got " + got + ", want " + want);
}
`
	cmd := exec.Command(node, "-e", script,
		filepath.Join(root, "site", "js", "detectors.js"),
		filepath.Join(root, "site", "js", "scanner.js"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("browser contract failed: %v\n%s", err, output)
	}
}

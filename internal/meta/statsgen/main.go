// Command statsgen rewrites the project's marketing-asset stat blocks from the
// canonical counts in internal/meta. It is wired to `go generate ./...` via the
// directive in internal/meta/counts.go.
//
// It only edits text inside a "stats:begin" / "stats:end" marker pair, so the
// surrounding markup and any context-specific numbers elsewhere in the file
// (verification tiers, historical highlights, coverage progressions) are never
// touched. With -check it verifies the files are up to date instead of writing,
// exiting non-zero on drift; this mode backs the guard test and CI.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/HodeTech/leakwatch/internal/meta"
)

const (
	beginMarker = "stats:begin"
	endMarker   = "stats:end"
)

// managedFiles are rewritten relative to the repository root.
var managedFiles = []string{
	"docs/assets/banner.html",
	"site/assets/og.svg",
}

// replacement pairs a noun-anchored pattern with its canonical replacement.
// Anchoring on the trailing noun keeps unrelated numbers (and the marker text
// itself) untouched.
type replacement struct {
	re   *regexp.Regexp
	with string
}

func replacements() []replacement {
	capabilities := meta.VerificationCapabilityCounts()
	return []replacement{
		{regexp.MustCompile(`\d+ detectors`), fmt.Sprintf("%d detectors", meta.Detectors)},
		{regexp.MustCompile(`\d+ (?:live verifiers|direct-live checks)`), fmt.Sprintf("%d direct-live checks", capabilities.Live)},
		{regexp.MustCompile(`\d+ sources`), fmt.Sprintf("%d sources", meta.Sources)},
		{regexp.MustCompile(`\d+ output formats`), fmt.Sprintf("%d output formats", meta.OutputFormats)},
	}
}

func main() {
	check := flag.Bool("check", false, "verify files are up to date instead of writing")
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fail(err)
	}

	var stale []string
	for _, rel := range managedFiles {
		path := filepath.Join(root, rel)
		orig, err := os.ReadFile(path)
		if err != nil {
			fail(fmt.Errorf("read %s: %w", rel, err))
		}
		updated, err := rewrite(string(orig))
		if err != nil {
			fail(fmt.Errorf("%s: %w", rel, err))
		}
		if updated == string(orig) {
			continue
		}
		if *check {
			stale = append(stale, rel)
			continue
		}
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			fail(fmt.Errorf("write %s: %w", rel, err))
		}
		fmt.Printf("updated %s\n", rel)
	}

	if len(stale) > 0 {
		fail(fmt.Errorf("stat blocks out of date in: %s\nrun `go generate ./...` and re-render the PNGs",
			strings.Join(stale, ", ")))
	}
}

// rewrite applies the canonical counts inside the stats marker region and
// returns the updated content. It errors when the markers are missing so an
// unmarked (silently unmanaged) asset is caught rather than ignored.
func rewrite(content string) (string, error) {
	begin := strings.Index(content, beginMarker)
	end := strings.Index(content, endMarker)
	if begin == -1 || end == -1 || end < begin {
		return "", fmt.Errorf("missing %q/%q markers", beginMarker, endMarker)
	}
	region := content[begin:end]
	for _, r := range replacements() {
		region = r.re.ReplaceAllString(region, r.with)
	}
	return content[:begin] + region + content[end:], nil
}

// repoRoot walks up from the working directory to the module root (the first
// directory containing go.mod), so the command works both under `go generate`
// (run from internal/meta) and under `go test` (run from the package dir).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found searching upward from %s", dir)
		}
		dir = parent
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "statsgen:", err)
	os.Exit(1)
}

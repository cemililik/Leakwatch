package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManagedAssetsUpToDate fails when a marketing asset's stat block no longer
// matches internal/meta — i.e. a count was bumped but `go generate ./...` was
// not run. It validates the HTML/SVG sources; the derived PNG is visually
// reviewed separately. It runs as part of `go test ./...`, so CI catches source
// drift without a dedicated workflow step.
func TestManagedAssetsUpToDate(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	for _, rel := range managedFiles {
		orig, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		updated, err := rewrite(string(orig))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if updated != string(orig) {
			t.Errorf("%s stat block is stale; run `go generate ./...` and re-render its PNG", rel)
		}
	}
}

func TestRewriteMigratesLegacyLiveVerifierLabel(t *testing.T) {
	input := "<!-- stats:begin -->54 live verifiers<!-- stats:end -->"
	got, err := rewrite(input)
	if err != nil {
		t.Fatalf("rewrite legacy label: %v", err)
	}
	want := "<!-- stats:begin -->41 direct-live checks<!-- stats:end -->"
	if got != want {
		t.Fatalf("rewrite legacy label = %q, want %q", got, want)
	}
}

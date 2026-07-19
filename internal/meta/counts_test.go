package meta

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countPackageDirs returns the number of immediate subdirectories of dir that
// contain at least one .go file, i.e. the number of Go packages nested one
// level under dir. Hidden directories (".git", etc.) and "testdata" are
// skipped.
func countPackageDirs(t *testing.T, dir string) int {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "read %s", dir)

	count := 0
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || e.Name() == "testdata" {
			continue
		}

		pkgDir := filepath.Join(dir, e.Name())
		pkgEntries, err := os.ReadDir(pkgDir)
		require.NoError(t, err, "read %s", pkgDir)

		for _, pe := range pkgEntries {
			if !pe.IsDir() && strings.HasSuffix(pe.Name(), ".go") {
				count++
				break
			}
		}
	}
	return count
}

// TestSources_MatchSourcePackageDirectories guards meta.Sources against
// silent drift: unlike Detectors/Verifiers (checked against detector.All() /
// verifier.All() in cmd/stats_test.go), Sources is a golden constant with no
// runtime registry to check against (see the package doc). Each scan source
// lives in its own subpackage under internal/source, so counting those
// subpackages is the closest available proxy for "reality" and catches the
// case where a new source package is added (or removed) without updating
// this constant.
func TestSources_MatchSourcePackageDirectories(t *testing.T) {
	got := countPackageDirs(t, filepath.Join("..", "source"))
	assert.Equal(t, Sources, got,
		"meta.Sources drifted from the number of internal/source subpackages; "+
			"update internal/meta then run `go generate ./...`")
}

// TestOutputFormats_MatchOutputPackageDirectories is the OutputFormats
// counterpart of TestSources_MatchSourcePackageDirectories: each output
// formatter lives in its own subpackage under internal/output, so counting
// those subpackages catches a new/removed formatter that forgot to update
// the golden constant.
func TestOutputFormats_MatchOutputPackageDirectories(t *testing.T) {
	got := countPackageDirs(t, filepath.Join("..", "output"))
	assert.Equal(t, OutputFormats, got,
		"meta.OutputFormats drifted from the number of internal/output subpackages; "+
			"update internal/meta then run `go generate ./...`")
}

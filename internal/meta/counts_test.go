package meta

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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
	assert.Len(t, OutputFormatNames(), OutputFormats,
		"meta.OutputFormatList and meta.OutputFormats must change together")

	seen := make(map[string]struct{}, OutputFormats)
	for _, format := range OutputFormatNames() {
		assert.Regexp(t, regexp.MustCompile(`^[a-z][a-z0-9-]*$`), format)
		if _, duplicate := seen[format]; duplicate {
			t.Errorf("duplicate output format %q", format)
		}
		seen[format] = struct{}{}
		assert.True(t, IsOutputFormat(format))
	}
	assert.False(t, IsOutputFormat(""))
	assert.False(t, IsOutputFormat("unknown"))
}

func TestReleaseMetadata_MatchesPublishedDocumentation(t *testing.T) {
	assert.Regexp(t, regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`), ReleaseVersion)
	assert.Regexp(t, regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`), ReleaseDate)
	_, err := time.Parse(time.DateOnly, ReleaseDate)
	require.NoError(t, err, "ReleaseDate must be a real ISO 8601 calendar date")

	changelog, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	require.NoError(t, err)
	assert.Contains(t, string(changelog), "## ["+ReleaseVersion+"] - "+ReleaseDate,
		"release metadata must identify a published changelog entry")

	roadmap, err := os.ReadFile(filepath.Join("..", "..", "docs", "05-ROADMAP.md"))
	require.NoError(t, err)
	assert.Contains(t, string(roadmap),
		"| Review Remediation Release | Released | `"+ReleaseVersion+"` | "+ReleaseDate+" |",
		"roadmap release record must match canonical release metadata")
	assert.Contains(t, string(roadmap),
		"| Phase 9 — Detection Accuracy & FP Reduction | Planned | `v1.8.0` | — |",
		"the published v1.7.0 tag must not still be assigned to planned Phase 9")
	assert.NotContains(t, string(roadmap),
		"| Phase 9 — Detection Accuracy & FP Reduction | Planned | `"+ReleaseVersion+"` | — |")
	assert.Contains(t, string(roadmap), "| Broaden OpenAI key coverage | Delivered in `v1.7.0` |")
	assert.Contains(t, string(roadmap), "| GitHub fine-grained PAT support | Delivered in `v1.7.0` |")
}

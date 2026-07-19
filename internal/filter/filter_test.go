package filter

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsExcludedExtension_BinaryExe_ReturnsTrue(t *testing.T) {
	assert.True(t, IsExcludedExtension("app.exe", nil))
}

func TestIsExcludedExtension_ImagePng_ReturnsTrue(t *testing.T) {
	assert.True(t, IsExcludedExtension("logo.png", nil))
}

func TestIsExcludedExtension_GoFile_ReturnsFalse(t *testing.T) {
	assert.False(t, IsExcludedExtension("main.go", nil))
}

func TestIsExcludedExtension_CustomExt_ReturnsTrue(t *testing.T) {
	assert.True(t, IsExcludedExtension("data.dat", []string{".dat"}))
}

func TestIsExcludedExtension_CaseInsensitive_ReturnsTrue(t *testing.T) {
	assert.True(t, IsExcludedExtension("file.PNG", nil))
}

func TestIsExcludedExtension_NoExtension_ReturnsFalse(t *testing.T) {
	assert.False(t, IsExcludedExtension("Makefile", nil))
}

func TestIsBinaryFile_TextContent_ReturnsFalse(t *testing.T) {
	assert.False(t, IsBinaryFile([]byte("hello world")))
}

func TestIsBinaryFile_NullByte_ReturnsTrue(t *testing.T) {
	assert.True(t, IsBinaryFile([]byte("hello\x00world")))
}

func TestIsBinaryFile_Empty_ReturnsFalse(t *testing.T) {
	assert.False(t, IsBinaryFile([]byte{}))
}

func TestIsBinaryFile_NullAtStart_ReturnsTrue(t *testing.T) {
	assert.True(t, IsBinaryFile([]byte{0, 1, 2, 3}))
}

func TestIsBinaryFile_NullAtBoundary_ReturnsTrue(t *testing.T) {
	// Null byte at exactly position 8191 (last checked byte)
	data := make([]byte, 8192)
	for i := range data {
		data[i] = 'A'
	}
	data[8191] = 0
	assert.True(t, IsBinaryFile(data))
}

func TestIsBinaryFile_NullBeyondBoundary_ReturnsFalse(t *testing.T) {
	// Null byte at position 8192 (beyond check window)
	data := make([]byte, 8193)
	for i := range data {
		data[i] = 'A'
	}
	data[8192] = 0
	assert.False(t, IsBinaryFile(data))
}

func TestIsBinaryFile_UTF16LE_ReturnsFalse(t *testing.T) {
	// UTF-16LE encodes every ASCII character with a trailing 0x00 byte; without
	// a BOM exemption this would always be misclassified as binary.
	data := []byte{0xFF, 0xFE, 'h', 0x00, 'i', 0x00}
	assert.False(t, IsBinaryFile(data))
}

func TestIsBinaryFile_UTF16BE_ReturnsFalse(t *testing.T) {
	data := []byte{0xFE, 0xFF, 0x00, 'h', 0x00, 'i'}
	assert.False(t, IsBinaryFile(data))
}

func TestIsBinaryFile_ShortDataNoBOM_ReturnsFalse(t *testing.T) {
	// A single byte cannot carry a BOM; must not panic on the BOM length check.
	assert.False(t, IsBinaryFile([]byte{'A'}))
	assert.False(t, IsBinaryFile([]byte{}))
}

func TestIsBinaryFile_NullBytesWithoutBOM_StillReturnsTrue(t *testing.T) {
	// The BOM exemption must not weaken the heuristic for genuinely binary data
	// that happens to not start with a BOM.
	data := []byte{'h', 0x00, 'i', 0x00}
	assert.True(t, IsBinaryFile(data))
}

func TestMatchesGlob_SimpleExtension_ReturnsTrue(t *testing.T) {
	assert.True(t, MatchesGlob("config.yaml", []string{"*.yaml"}))
}

func TestMatchesGlob_NoMatch_ReturnsFalse(t *testing.T) {
	assert.False(t, MatchesGlob("main.go", []string{"*.yaml"}))
}

func TestMatchesGlob_ExactFilename_ReturnsTrue(t *testing.T) {
	assert.True(t, MatchesGlob("go.sum", []string{"go.sum"}))
}

func TestMatchesGlob_EmptyPatterns_ReturnsFalse(t *testing.T) {
	assert.False(t, MatchesGlob("file.go", nil))
}

func TestMatchesGlob_BaseName_ReturnsTrue(t *testing.T) {
	assert.True(t, MatchesGlob("src/main.go", []string{"*.go"}))
}

func TestMatchesGlob_DoubleStar_MatchesNestedPath(t *testing.T) {
	assert.True(t, MatchesGlob("vendor/github.com/pkg/file.go", []string{"vendor/**"}))
}

func TestMatchesGlob_DoubleStarPrefix_MatchesAnyDir(t *testing.T) {
	assert.True(t, MatchesGlob("src/deep/nested/file.lock", []string{"**/*.lock"}))
}

func TestMatchesGlob_DoubleStarMiddle_MatchesPath(t *testing.T) {
	assert.True(t, MatchesGlob("node_modules/pkg/index.js", []string{"node_modules/**"}))
}

func TestMatchesGlob_DoubleStarNoMatch_ReturnsFalse(t *testing.T) {
	assert.False(t, MatchesGlob("src/main.go", []string{"vendor/**"}))
}

func TestMatchesGlob_SlashPatternAgainstBackslashPath_MatchesOnAnyOS(t *testing.T) {
	// Exclude-path patterns are conventionally written with "/" (e.g.
	// "config/secret.pem"). On Windows, filepath.Rel produces backslash-
	// separated relative paths, so the non-"**" fallback branch must normalize
	// both sides with filepath.ToSlash before calling filepath.Match, which
	// otherwise treats "/" as a literal (not the platform separator).
	assert.True(t, MatchesGlob(`config\secret.pem`, []string{"config/secret.pem"}))
}

func TestMatchSegments_ManyDoubleStarTokens_DoesNotBlowUpAndMatchesCorrectly(t *testing.T) {
	// Regression test for the algorithmic-complexity fix: naive backtracking
	// recursion on chained "**" tokens against a deep, non-matching path would
	// previously explore every split-position combination. The DP rewrite
	// bounds this to O(len(pattern)*len(path)) regardless of the number of
	// "**" tokens. This pattern has 8 "**" tokens; a deep non-matching path
	// must resolve quickly instead of hanging.
	deepPath := "a/" + strings.Repeat("seg/", 40) + "nomatch-tail"
	pattern := "a/**/**/**/**/**/**/**/**/never-matches"

	done := make(chan bool, 1)
	go func() {
		done <- MatchesGlob(deepPath, []string{pattern})
	}()

	select {
	case got := <-done:
		assert.False(t, got)
	case <-time.After(5 * time.Second):
		t.Fatal("matching with many ** tokens did not complete in time — possible complexity regression")
	}
}

func TestMatchSegments_ManyDoubleStarTokens_MatchesWhenExpected(t *testing.T) {
	deepPath := "a/x1/x2/x3/x4/x5/tail.txt"
	pattern := "a/**/**/**/**/**/tail.txt"
	assert.True(t, MatchesGlob(deepPath, []string{pattern}))
}

func TestMatchesGlob_InvalidPattern_TreatedAsNonMatch(t *testing.T) {
	// An invalid glob must never match and must not panic; it is logged and
	// treated as a non-match so one malformed exclude cannot break filtering.
	assert.False(t, MatchesGlob("file.go", []string{"[unclosed"}))
}

func TestMatchesGlob_InvalidSegmentInsideDoubleStar_TreatedAsNonMatchNotPanic(t *testing.T) {
	// A malformed non-"**" segment inside a "**" pattern must surface as a
	// logged non-match (like the sibling matchGlob/matchDirPrefix branches),
	// not panic and not silently succeed.
	assert.False(t, MatchesGlob("src/deep/file.go", []string{"src/**/[unclosed"}))
}

func TestMatchesGlob_TrailingSlashDir_MatchesSubtree(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"top-level file under dir", "build/", "build/output.txt", true},
		{"nested file under dir", "build/", "build/sub/deep.go", true},
		{"dir nested deeper in path", "build/", "src/build/artifact.o", true},
		{"node_modules subtree", "node_modules/", "node_modules/pkg/index.js", true},
		{"unrelated path", "build/", "src/main.go", false},
		{"directory itself with no child is not matched", "build/", "build", false},
		{"glob directory name", "build*/", "builds/output.txt", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchesGlob(tt.path, []string{tt.pattern}))
		})
	}
}

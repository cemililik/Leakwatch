package meta

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	markdownLinkPattern  = regexp.MustCompile(`!?\[[^\]\n]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	fullVersionPattern   = regexp.MustCompile(`\bv[0-9]+\.[0-9]+\.[0-9]+\b`)
	leakwatchPinPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)github\.com/hodetech/leakwatch@(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)ghcr\.io/hodetech/leakwatch:(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)LEAKWATCH_VERSION[[:space:]]*:[[:space:]]*['"]?(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)(?:^|[[:space:]])rev[[:space:]]*:[[:space:]]*(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)(?:^|[[:space:]])version[[:space:]]*:[[:space:]]*['"]?(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)leakwatch[[:space:]]+(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)leakwatch[[:space:]]+(?:version|sürümü).*?(v[0-9]+\.[0-9]+\.[0-9]+)`),
	}
)

type markdownLine struct {
	number int
	text   string
}

func TestSupplementalGuides_DeclareCanonicalManualBoundary(t *testing.T) {
	guides, err := filepath.Glob(filepath.Join("..", "..", "docs", "guides", "*.md"))
	require.NoError(t, err)
	require.NotEmpty(t, guides)

	for _, path := range guides {
		if filepath.Base(path) == "README.md" {
			continue
		}
		contents, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		text := string(contents)
		assert.Contains(t, text, "> **Documentation role:** Supplemental", path)
		assert.Contains(t, text, "(../user-manuals/en/", path)
	}
}

func TestDocumentation_LeakwatchReleasePinsAreCurrentOrHistorical(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{filepath.Join(root, "README.md")}
	for _, dir := range []string{
		filepath.Join(root, "docs", "guides"),
		filepath.Join(root, "docs", "user-manuals"),
	} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
				paths = append(paths, path)
			}
			return nil
		})
		require.NoError(t, err)
	}

	for _, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		lines := strings.Split(string(contents), "\n")
		for lineIndex, line := range lines {
			for _, pin := range leakwatchReleasePins(path, line) {
				if pin == ReleaseVersion || hasHistoricalVersionMarker(lines, lineIndex) {
					continue
				}
				t.Errorf("%s:%d uses stale Leakwatch pin %s; use %s or precede an intentionally historical example with <!-- leakwatch-version: historical -->",
					filepath.ToSlash(path), lineIndex+1, pin, ReleaseVersion)
			}
		}
	}
}

func leakwatchReleasePins(path, line string) []string {
	var pins []string
	for _, pattern := range leakwatchPinPatterns {
		for _, match := range pattern.FindAllStringSubmatch(line, -1) {
			pins = append(pins, match[1])
		}
	}

	// In these installation tables, :vX.Y.Z denotes the Leakwatch image rather
	// than an arbitrary application image used elsewhere in the manuals.
	base := filepath.ToSlash(path)
	if strings.HasSuffix(base, "/ci-cd/docker-usage.md") &&
		strings.HasPrefix(strings.TrimSpace(line), "|") && strings.Contains(line, "`:v") {
		pins = append(pins, fullVersionPattern.FindAllString(line, -1)...)
	}
	return pins
}

func hasHistoricalVersionMarker(lines []string, lineIndex int) bool {
	const marker = "<!-- leakwatch-version: historical -->"
	for i := lineIndex; i >= 0 && i >= lineIndex-4; i-- {
		if strings.Contains(lines[i], marker) {
			return true
		}
	}
	return false
}

func TestDocumentation_RelativeMarkdownLinksResolve(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "CONTRIBUTING.md"),
		filepath.Join(root, "site", "README.md"),
	}
	for _, dir := range []string{filepath.Join(root, "docs")} {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
				paths = append(paths, path)
			}
			return nil
		})
		require.NoError(t, err)
	}

	for _, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, line := range markdownLinesOutsideFences(string(contents)) {
			for _, match := range markdownLinkPattern.FindAllStringSubmatch(line.text, -1) {
				destination := strings.Trim(match[1], "<>")
				if destination == "" || strings.HasPrefix(destination, "#") ||
					strings.HasPrefix(destination, "/") || strings.Contains(destination, "://") ||
					strings.HasPrefix(destination, "mailto:") {
					continue
				}
				if cut := strings.IndexAny(destination, "?#"); cut >= 0 {
					destination = destination[:cut]
				}
				if destination == "" {
					continue
				}
				target := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(destination)))
				if _, statErr := os.Stat(target); statErr != nil {
					t.Errorf("%s:%d has unresolved relative link %q: %v",
						filepath.ToSlash(path), line.number, match[1], statErr)
				}
			}
		}
	}
}

func markdownLinesOutsideFences(contents string) []markdownLine {
	lines := strings.Split(contents, "\n")
	result := make([]markdownLine, 0, len(lines))
	inFence := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if !inFence {
			result = append(result, markdownLine{number: index + 1, text: line})
		}
	}
	return result
}

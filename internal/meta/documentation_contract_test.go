package meta

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	fullVersionPattern         = regexp.MustCompile(`\bv[0-9]+\.[0-9]+\.[0-9]+\b`)
	directLeakwatchPinPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)github\.com/hodetech/leakwatch@(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)ghcr\.io/hodetech/leakwatch:(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)LEAKWATCH_VERSION[[:space:]]*[:=][[:space:]]*['\"]?(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)leakwatch[[:space:]]+(v[0-9]+\.[0-9]+\.[0-9]+)`),
		regexp.MustCompile(`(?i)leakwatch[[:space:]]+(?:version|sürümü).*?(v[0-9]+\.[0-9]+\.[0-9]+)`),
	}
	contextualVersionAssignment = regexp.MustCompile(`(?im)(?:^|[[:space:]])(?:rev|version)[[:space:]]*[:=][[:space:]]*['\"]?(v[0-9]+\.[0-9]+\.[0-9]+)`)
	leakwatchBlockContext       = regexp.MustCompile(`(?i)(?:github\.com/hodetech/leakwatch|ghcr\.io/hodetech/leakwatch|hodetech/leakwatch@|\bleakwatch\b)`)
	historicalVersionMarker     = regexp.MustCompile(`(?i)<!--[[:space:]]*leakwatch-version:[[:space:]]*historical[[:space:]]+(v[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*-->`)
)

type documentationBlock struct {
	startLine int
	text      string
}

type versionPin struct {
	line    int
	version string
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

func TestDocumentation_LeakwatchReleasePinsAreCurrentOrExplicitlyHistorical(t *testing.T) {
	root := filepath.Join("..", "..")
	paths, err := currentDocumentationMarkdownPaths(root)
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		for _, block := range markdownContractBlocks(string(contents)) {
			for _, pin := range leakwatchReleasePins(path, block) {
				if pin.version == ReleaseVersion || blockMarksHistoricalVersion(block.text, pin.version) {
					continue
				}
				t.Errorf("%s:%d uses stale Leakwatch pin %s; use %s or mark the same logical example with <!-- leakwatch-version: historical %s -->",
					filepath.ToSlash(path), pin.line, pin.version, ReleaseVersion, pin.version)
			}
		}
	}
}

func TestLeakwatchReleasePins_ContextAndHistoricalMarkerMatrix(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		contents   string
		wantPins   []string
		wantLines  []int
		wantExempt bool
	}{
		{name: "environment equals", contents: "LEAKWATCH_VERSION=v1.6.0", wantPins: []string{"v1.6.0"}, wantLines: []int{1}},
		{name: "environment YAML", contents: "LEAKWATCH_VERSION: 'v1.6.0'", wantPins: []string{"v1.6.0"}, wantLines: []int{1}},
		{name: "Leakwatch action input", contents: "```yaml\nuses: HodeTech/Leakwatch@v1\nwith:\n  version = v1.6.0\n```", wantPins: []string{"v1.6.0"}, wantLines: []int{4}},
		{name: "Leakwatch pre-commit rev", contents: "```yaml\n- repo: https://github.com/HodeTech/Leakwatch\n  rev: v1.6.0\n```", wantPins: []string{"v1.6.0"}, wantLines: []int{3}},
		{name: "unrelated version assignment", contents: "```yaml\nname: unrelated\nversion: v2.3.0\n```"},
		{name: "exact historical marker", contents: "<!-- leakwatch-version: historical v1.6.0 -->\n\n```bash\nleakwatch v1.6.0\n```", wantPins: []string{"v1.6.0"}, wantLines: []int{4}, wantExempt: true},
		{name: "marker cannot exempt different pin", contents: "<!-- leakwatch-version: historical v1.5.0 -->\n\nleakwatch v1.6.0", wantPins: []string{"v1.6.0"}, wantLines: []int{3}},
		{name: "marker cannot exempt later block", contents: "<!-- leakwatch-version: historical v1.6.0 -->\n\nleakwatch v1.6.0\n\nUnrelated paragraph.\n\nleakwatch v1.6.0", wantPins: []string{"v1.6.0", "v1.6.0"}, wantLines: []int{3, 7}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			var gotLines []int
			var exemptions []bool
			for _, block := range markdownContractBlocks(tc.contents) {
				for _, pin := range leakwatchReleasePins(tc.path, block) {
					got = append(got, pin.version)
					gotLines = append(gotLines, pin.line)
					exemptions = append(exemptions, blockMarksHistoricalVersion(block.text, pin.version))
				}
			}
			assert.Equal(t, tc.wantPins, got)
			assert.Equal(t, tc.wantLines, gotLines)
			if tc.wantExempt {
				assert.Equal(t, []bool{true}, exemptions)
			} else if len(exemptions) > 0 {
				assert.False(t, exemptions[len(exemptions)-1])
			}
		})
	}
}

func TestEntropyPolicyDocs_MatchEngineContract(t *testing.T) {
	root := filepath.Join("..", "..")
	oldADR, err := os.ReadFile(filepath.Join(root, "docs", "decisions", "ADR-0005-pattern-matching.md"))
	require.NoError(t, err)
	assert.Contains(t, string(oldADR), "**Status:** Superseded by [ADR-0010]")

	currentADR, err := os.ReadFile(filepath.Join(root, "docs", "decisions", "ADR-0010-entropy-gating-policy.md"))
	require.NoError(t, err)
	for _, contract := range []string{"EntropyBased", "EntropyGated", "generic-api-key", "structural provider findings", "per-rule `entropy` threshold"} {
		assert.Contains(t, string(currentADR), contract)
	}

	engineSource, err := os.ReadFile(filepath.Join(root, "internal", "engine", "engine.go"))
	require.NoError(t, err)
	assert.Contains(t, string(engineSource), "isEntropyGated(det, raw)")
	genericSource, err := os.ReadFile(filepath.Join(root, "internal", "detector", "generic", "generic_api_key.go"))
	require.NoError(t, err)
	assert.Contains(t, string(genericSource), "func (d *APIKeyDetector) EntropyBased() bool { return true }")
	assert.Contains(t, string(genericSource), "func (d *APIKeyDetector) EntropyGated(raw detector.RawFinding) bool")

	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?is)entropy.{0,120}display-only`),
		regexp.MustCompile(`(?is)engine never gates or suppresses.{0,120}entropy`),
		regexp.MustCompile(`(?is)global entropy gate.{0,120}(?:planned|not yet implemented)`),
	}
	for _, dir := range []string{
		filepath.Join(root, "docs", "architecture"),
		filepath.Join(root, "docs", "guides"),
		filepath.Join(root, "docs", "user-manuals"),
	} {
		walkErr := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
				return nil
			}
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, pattern := range forbidden {
				assert.False(t, pattern.Match(contents), "%s contains superseded entropy policy matching %s", filepath.ToSlash(path), pattern)
			}
			return nil
		})
		require.NoError(t, walkErr)
	}
}

func currentDocumentationMarkdownPaths(root string) ([]string, error) {
	skipDirs := map[string]struct{}{
		".git": {}, "node_modules": {}, "vendor": {}, "dist": {}, "review": {},
	}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root {
				if _, skip := skipDirs[entry.Name()]; skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if strings.EqualFold(filepath.Base(rel), "CHANGELOG.md") || rel == "docs/05-ROADMAP.md" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

func markdownContractBlocks(contents string) []documentationBlock {
	lines := strings.Split(strings.ReplaceAll(contents, "\r\n", "\n"), "\n")
	var blocks []documentationBlock
	for index := 0; index < len(lines); {
		for index < len(lines) && strings.TrimSpace(lines[index]) == "" {
			index++
		}
		if index >= len(lines) {
			break
		}
		start := index
		prefix := ""
		if historicalVersionMarker.MatchString(lines[index]) {
			index++
			for index < len(lines) && strings.TrimSpace(lines[index]) == "" {
				index++
			}
			prefix = strings.Join(lines[start:index], "\n") + "\n"
			if index >= len(lines) {
				blocks = append(blocks, documentationBlock{startLine: start + 1, text: prefix})
				break
			}
		}

		trimmed := strings.TrimSpace(lines[index])
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fence := trimmed[:3]
			end := index + 1
			for end < len(lines) {
				if strings.HasPrefix(strings.TrimSpace(lines[end]), fence) {
					end++
					break
				}
				end++
			}
			blocks = append(blocks, documentationBlock{startLine: start + 1, text: prefix + strings.Join(lines[index:end], "\n")})
			index = end
			continue
		}

		end := index + 1
		for end < len(lines) && strings.TrimSpace(lines[end]) != "" {
			if next := strings.TrimSpace(lines[end]); strings.HasPrefix(next, "```") || strings.HasPrefix(next, "~~~") {
				break
			}
			end++
		}
		blocks = append(blocks, documentationBlock{startLine: start + 1, text: prefix + strings.Join(lines[index:end], "\n")})
		index = end
	}
	return blocks
}

func leakwatchReleasePins(path string, block documentationBlock) []versionPin {
	byVersionAndLine := make(map[versionPin]struct{})
	collect := func(pattern *regexp.Regexp) {
		for _, match := range pattern.FindAllStringSubmatchIndex(block.text, -1) {
			if len(match) < 4 || match[2] < 0 {
				continue
			}
			version := block.text[match[2]:match[3]]
			line := block.startLine + strings.Count(block.text[:match[2]], "\n")
			byVersionAndLine[versionPin{line: line, version: version}] = struct{}{}
		}
	}
	for _, pattern := range directLeakwatchPinPatterns {
		collect(pattern)
	}
	if leakwatchBlockContext.MatchString(block.text) {
		collect(contextualVersionAssignment)
	}

	base := filepath.ToSlash(path)
	if strings.HasSuffix(base, "/ci-cd/docker-usage.md") && strings.Contains(block.text, "`:v") {
		for _, location := range fullVersionPattern.FindAllStringIndex(block.text, -1) {
			version := block.text[location[0]:location[1]]
			line := block.startLine + strings.Count(block.text[:location[0]], "\n")
			byVersionAndLine[versionPin{line: line, version: version}] = struct{}{}
		}
	}

	pins := make([]versionPin, 0, len(byVersionAndLine))
	for pin := range byVersionAndLine {
		pins = append(pins, pin)
	}
	sort.Slice(pins, func(i, j int) bool {
		if pins[i].line == pins[j].line {
			return pins[i].version < pins[j].version
		}
		return pins[i].line < pins[j].line
	})
	return pins
}

func blockMarksHistoricalVersion(block, version string) bool {
	for _, match := range historicalVersionMarker.FindAllStringSubmatch(block, -1) {
		if strings.EqualFold(match[1], version) {
			return true
		}
	}
	return false
}

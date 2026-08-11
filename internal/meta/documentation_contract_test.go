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
	"gopkg.in/yaml.v3"
)

const releaseVersionTokenPattern = `v[0-9]+\.[0-9]+\.[0-9]+(?:[-_][0-9A-Za-z]+(?:[._-][0-9A-Za-z]+)*)?`

var (
	releaseVersionToken        = regexp.MustCompile(`\b(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`)
	releaseVersionTokenExact   = regexp.MustCompile(`^` + releaseVersionTokenPattern + `$`)
	directLeakwatchPinPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)github\.com/hodetech/leakwatch@(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`),
		regexp.MustCompile(`(?i)(?:^|[^0-9A-Za-z/])hodetech/leakwatch@(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`),
		regexp.MustCompile(`(?i)ghcr\.io/hodetech/leakwatch:(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`),
		regexp.MustCompile(`(?i)LEAKWATCH_VERSION[[:space:]]*[:=][[:space:]]*['\"]?(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`),
		regexp.MustCompile(`(?i)leakwatch[[:space:]]+(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`),
		regexp.MustCompile(`(?i)leakwatch[[:space:]]+(?:version|sürümü).*?(` + releaseVersionTokenPattern + `)(?:[^0-9A-Za-z._-]|$)`),
	}
	historicalVersionMarker = regexp.MustCompile(`(?i)<!--[[:space:]]*leakwatch-version:[[:space:]]*historical[[:space:]]+(` + releaseVersionTokenPattern + `)[[:space:]]*-->`)
)

type documentationBlock struct {
	startLine          int
	text               string
	leakwatchImageTags bool
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
		{name: "environment equals", contents: "LEAKWATCH_VERSION = v1.6.0", wantPins: []string{"v1.6.0"}, wantLines: []int{1}},
		{name: "environment YAML", contents: "LEAKWATCH_VERSION: 'v1.6.0'", wantPins: []string{"v1.6.0"}, wantLines: []int{1}},
		{name: "Leakwatch action input", contents: "```yaml\n- uses: HodeTech/Leakwatch@v1\n  with:\n    version: v1.6.0\n- uses: actions/setup-node@v4\n  with:\n    version: v22.3.0\n```", wantPins: []string{"v1.6.0"}, wantLines: []int{4}},
		{name: "exact Leakwatch action pin", contents: "```yaml\n- uses: HodeTech/Leakwatch@v1.6.0\n```", wantPins: []string{"v1.6.0"}, wantLines: []int{2}},
		{name: "Leakwatch pre-commit rev", contents: "```yaml\n- repo: https://github.com/HodeTech/Leakwatch\n  rev: v1.6.0\n```", wantPins: []string{"v1.6.0"}, wantLines: []int{3}},
		{name: "unrelated rev in same YAML", contents: "```yaml\n- repo: https://github.com/HodeTech/Leakwatch\n  rev: v1.7.0\n- repo: https://example.com/tool\n  rev: v9.8.7\n```", wantPins: []string{"v1.7.0"}, wantLines: []int{3}},
		{name: "unrelated version assignment", contents: "```yaml\nname: unrelated\nversion: v2.3.0\n```"},
		{name: "suffix cannot hide behind current stable prefix", contents: "LEAKWATCH_VERSION=v1.7.0-typo", wantPins: []string{"v1.7.0-typo"}, wantLines: []int{1}},
		{name: "contextual image tag table", contents: "```text\nghcr.io/hodetech/leakwatch\n```\n\nAvailable tags:\n\n| Tag | Description |\n|---|---|\n| `:v1.6.0` | stale |", wantPins: []string{"v1.6.0"}, wantLines: []int{9}},
		{name: "bare tag for unrelated image is ignored", contents: "Available tags:\n\n| Tag | Description |\n|---|---|\n| `:v9.8.7` | unrelated |"},
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
	assert.Contains(t, string(oldADR), "**Status:** Amended by [ADR-0010]")

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

func TestSlackScopeDocumentation_ContainsExecutableRequiredSet(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{
		filepath.Join(root, "docs", "guides", "configuration.md"),
		filepath.Join(root, "docs", "guides", "slack-scanning.md"),
		filepath.Join(root, "docs", "user-manuals", "en", "scanning", "slack.md"),
		filepath.Join(root, "docs", "user-manuals", "tr", "scanning", "slack.md"),
		filepath.Join(root, "site", "js", "manuals", "en.js"),
		filepath.Join(root, "site", "js", "manuals", "tr.js"),
	}
	scopes := []string{
		"channels:read", "channels:history", "groups:read", "groups:history",
		"im:read", "im:history", "mpim:read", "mpim:history", "files:read",
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		for _, scope := range scopes {
			assert.Contains(t, string(contents), scope, "%s is missing %s", filepath.ToSlash(path), scope)
		}
	}
}

func TestFindingWireSemanticsDocs_MatchEngine(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{
		filepath.Join(root, "docs", "user-manuals", "en", "getting-started", "how-it-works.md"),
		filepath.Join(root, "docs", "user-manuals", "tr", "getting-started", "how-it-works.md"),
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		text := string(contents)
		assert.Contains(t, text, "decimal(byteOffset)", path)
		assert.Contains(t, text, "detection.entropy.enabled", path)
		assert.NotContains(t, text, "sha256(detectorID + redacted + filePath + line)", path)
	}
	for _, path := range []string{
		filepath.Join(root, "docs", "user-manuals", "en", "getting-started", "introduction.md"),
		filepath.Join(root, "docs", "user-manuals", "tr", "getting-started", "introduction.md"),
	} {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(contents), "11")
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
		index = nextNonBlankLine(lines, index)
		if index >= len(lines) {
			break
		}
		start := index
		prefix, contentStart := documentationBlockPrefix(lines, index)
		if contentStart >= len(lines) {
			blocks = append(blocks, documentationBlock{startLine: start + 1, text: prefix})
			break
		}
		end := documentationBlockEnd(lines, contentStart)
		blocks = append(blocks, documentationBlock{startLine: start + 1, text: prefix + strings.Join(lines[contentStart:end], "\n")})
		index = end
	}
	markLeakwatchImageTagTables(blocks)
	return blocks
}

func nextNonBlankLine(lines []string, index int) int {
	for index < len(lines) && strings.TrimSpace(lines[index]) == "" {
		index++
	}
	return index
}

func documentationBlockPrefix(lines []string, index int) (string, int) {
	if !historicalVersionMarker.MatchString(lines[index]) {
		return "", index
	}
	contentStart := nextNonBlankLine(lines, index+1)
	return strings.Join(lines[index:contentStart], "\n") + "\n", contentStart
}

func documentationBlockEnd(lines []string, start int) int {
	trimmed := strings.TrimSpace(lines[start])
	if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
		return fencedDocumentationBlockEnd(lines, start, trimmed[:3])
	}
	end := start + 1
	for end < len(lines) && strings.TrimSpace(lines[end]) != "" && !startsMarkdownFence(lines[end]) {
		end++
	}
	return end
}

func fencedDocumentationBlockEnd(lines []string, start int, fence string) int {
	for end := start + 1; end < len(lines); end++ {
		if strings.HasPrefix(strings.TrimSpace(lines[end]), fence) {
			return end + 1
		}
	}
	return len(lines)
}

func startsMarkdownFence(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")
}

func markLeakwatchImageTagTables(blocks []documentationBlock) {
	pendingTagTable := false
	for index := range blocks {
		trimmed := strings.TrimSpace(blocks[index].text)
		if strings.HasPrefix(trimmed, "#") {
			pendingTagTable = false
		}
		if strings.Contains(strings.ToLower(blocks[index].text), "ghcr.io/hodetech/leakwatch") {
			pendingTagTable = true
		}
		if pendingTagTable && strings.HasPrefix(trimmed, "|") && strings.Contains(blocks[index].text, "`:v") {
			blocks[index].leakwatchImageTags = true
			pendingTagTable = false
		}
	}
}

func leakwatchReleasePins(_ string, block documentationBlock) []versionPin {
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
	for _, pin := range leakwatchYAMLPins(block) {
		byVersionAndLine[pin] = struct{}{}
	}

	if block.leakwatchImageTags {
		for _, location := range releaseVersionToken.FindAllStringSubmatchIndex(block.text, -1) {
			if len(location) < 4 || location[2] < 0 {
				continue
			}
			version := block.text[location[2]:location[3]]
			line := block.startLine + strings.Count(block.text[:location[2]], "\n")
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

func leakwatchYAMLPins(block documentationBlock) []versionPin {
	source, lineOffset := yamlSourceFromBlock(block.text)
	if strings.TrimSpace(source) == "" {
		return nil
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(source), &document); err != nil {
		return nil
	}
	var pins []versionPin
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node.Kind == yaml.MappingNode {
			values := yamlMappingValues(node)
			if repo := values["repo"]; repo != nil && isLeakwatchRepository(repo.Value) {
				if rev := values["rev"]; rev != nil {
					if version := releaseVersionTokenExact.FindString(rev.Value); version != "" {
						pins = append(pins, versionPin{
							line:    block.startLine + lineOffset + rev.Line - 1,
							version: version,
						})
					}
				}
			}
			if uses := values["uses"]; uses != nil && isLeakwatchAction(uses.Value) {
				if with := values["with"]; with != nil && with.Kind == yaml.MappingNode {
					if versionNode := yamlMappingValues(with)["version"]; versionNode != nil {
						if version := releaseVersionTokenExact.FindString(versionNode.Value); version != "" {
							pins = append(pins, versionPin{
								line:    block.startLine + lineOffset + versionNode.Line - 1,
								version: version,
							})
						}
					}
				}
			}
		}
		for _, child := range node.Content {
			walk(child)
		}
	}
	walk(&document)
	return pins
}

func yamlSourceFromBlock(block string) (string, int) {
	lines := strings.Split(block, "\n")
	for index, line := range lines {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(trimmed, "```yaml") && !strings.HasPrefix(trimmed, "```yml") &&
			!strings.HasPrefix(trimmed, "~~~yaml") && !strings.HasPrefix(trimmed, "~~~yml") {
			continue
		}
		fence := strings.TrimSpace(line)[:3]
		for end := index + 1; end < len(lines); end++ {
			if strings.HasPrefix(strings.TrimSpace(lines[end]), fence) {
				return strings.Join(lines[index+1:end], "\n"), index + 1
			}
		}
		return "", 0
	}
	return block, 0
}

func yamlMappingValues(mapping *yaml.Node) map[string]*yaml.Node {
	values := make(map[string]*yaml.Node, len(mapping.Content)/2)
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		key := mapping.Content[index]
		if key.Kind == yaml.ScalarNode {
			values[strings.ToLower(strings.TrimSpace(key.Value))] = mapping.Content[index+1]
		}
	}
	return values
}

func isLeakwatchRepository(value string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".git")
	return normalized == "https://github.com/hodetech/leakwatch" || normalized == "github.com/hodetech/leakwatch"
}

func isLeakwatchAction(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(normalized, "hodetech/leakwatch@") ||
		strings.HasPrefix(normalized, "github.com/hodetech/leakwatch@")
}

func blockMarksHistoricalVersion(block, version string) bool {
	for _, match := range historicalVersionMarker.FindAllStringSubmatch(block, -1) {
		if strings.EqualFold(match[1], version) {
			return true
		}
	}
	return false
}

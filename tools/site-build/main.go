// Command site-build compiles the Leakwatch user manuals and detector contracts
// into the static documentation website, and synchronizes release-version
// footers from internal/meta.
//
// Source layout:
//
//	docs/user-manuals/_meta.yaml                       navigation metadata
//	docs/user-manuals/<lang>/<section>/<page>.md       one Markdown page per topic
//
// Generated output (committed so the site needs no runtime build step):
//
//	site/js/manuals/_index.js     window.LW_MANUAL_INDEX  (navigation tree)
//	site/js/manuals/<lang>.js     window.LW_MANUAL[lang]  (rendered page HTML)
//
// The tool locates the repository root automatically by walking up from the
// current working directory until it finds docs/user-manuals/_meta.yaml, so it
// can be run from anywhere in the tree.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v3"
)

// meta mirrors docs/user-manuals/_meta.yaml.
type meta struct {
	Languages       []string      `yaml:"languages"`
	DefaultLanguage string        `yaml:"default_language"`
	Sections        []metaSection `yaml:"sections"`
}

type metaSection struct {
	ID    string            `yaml:"id"`
	Icon  string            `yaml:"icon"`
	Title map[string]string `yaml:"title"`
	Pages []metaPage        `yaml:"pages"`
}

type metaPage struct {
	ID    string            `yaml:"id"`
	Title map[string]string `yaml:"title"`
}

var manualIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// frontMatter is the YAML header of each Markdown page.
type frontMatter struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
}

// idx is the JSON shape written to _index.js.
type idx struct {
	Languages []string     `json:"languages"`
	Default   string       `json:"default"`
	Sections  []idxSection `json:"sections"`
}

type idxSection struct {
	ID    string            `json:"id"`
	Icon  string            `json:"icon"`
	Title map[string]string `json:"title"`
	Pages []idxPage         `json:"pages"`
}

type idxPage struct {
	ID    string            `json:"id"`
	Title map[string]string `json:"title"`
}

// pageDoc is one entry in a per-language bag.
type pageDoc struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	HTML        string `json:"html"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "site-build: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	strict := flag.Bool("strict", false, "fail if any manual page is missing for a declared language")
	flag.Parse()

	root, err := findRoot()
	if err != nil {
		return err
	}

	metaPath := filepath.Join(root, "docs", "user-manuals", "_meta.yaml")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	m, err := decodeManualMeta(metaBytes)
	if err != nil {
		return fmt.Errorf("parse meta: %w", err)
	}
	if len(m.Languages) == 0 {
		return fmt.Errorf("no languages declared in _meta.yaml")
	}
	manualsDir := filepath.Join(root, "docs", "user-manuals")
	if err := validateManualContract(manualsDir, m, *strict); err != nil {
		return err
	}

	// Build every generated artifact outside the committed site tree. A parser,
	// strict-missing-page, detector, or footer validation error can therefore
	// never leave a partially regenerated workspace behind.
	stageRoot, err := os.MkdirTemp("", "leakwatch-site-build-*")
	if err != nil {
		return fmt.Errorf("create site staging directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(stageRoot) }()

	outDir := filepath.Join(stageRoot, "js", "manuals")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create staging output dir: %w", err)
	}

	// Navigation index (language-independent).
	index := idx{Languages: m.Languages, Default: m.DefaultLanguage}
	for _, s := range m.Sections {
		sec := idxSection{ID: s.ID, Icon: s.Icon, Title: s.Title}
		for _, p := range s.Pages {
			sec.Pages = append(sec.Pages, idxPage{ID: p.ID, Title: p.Title})
		}
		index.Sections = append(index.Sections, sec)
	}
	if err := writeJSON(filepath.Join(outDir, "_index.js"), "window.LW_MANUAL_INDEX", index, true); err != nil {
		return err
	}

	md := newMarkdown()
	missing := 0

	for _, lang := range m.Languages {
		bag := map[string]pageDoc{}
		for _, s := range m.Sections {
			for _, p := range s.Pages {
				key := s.ID + "/" + p.ID
				src := filepath.Join(manualsDir, lang, s.ID, p.ID+".md")
				raw, err := os.ReadFile(src)
				if err != nil {
					missing++
					fmt.Fprintf(os.Stderr, "site-build: WARNING missing page %s [%s]\n", key, lang)
					continue
				}
				fm, body, err := splitFrontMatter(raw)
				if err != nil {
					return fmt.Errorf("front matter %s [%s]: %w", key, lang, err)
				}
				htmlOut, err := renderMarkdown(md, body, lang)
				if err != nil {
					return fmt.Errorf("render %s [%s]: %w", key, lang, err)
				}
				bag[key] = pageDoc{Title: fm.Title, Description: fm.Description, HTML: htmlOut}
			}
		}
		target := filepath.Join(outDir, lang+".js")
		assign := fmt.Sprintf("window.LW_MANUAL = window.LW_MANUAL || {};\nwindow.LW_MANUAL[%q]", lang)
		if err := writeJSON(target, assign, bag, false); err != nil {
			return err
		}
		fmt.Printf("site-build: wrote %s (%d pages)\n", filepath.Base(target), len(bag))
	}

	// Compile the in-browser playground detector set from internal/detector.
	jsDir := filepath.Join(stageRoot, "js")
	nDet, err := buildDetectors(root, jsDir, *strict)
	if err != nil {
		return err
	}
	fmt.Printf("site-build: wrote detectors.js (%d detectors)\n", nDet)

	if missing > 0 && *strict {
		return fmt.Errorf("%d manual page(s) missing (strict mode)", missing)
	}

	releaseVersion, err := readReleaseVersion(root)
	if err != nil {
		return err
	}
	footerCount, err := commitStagedSite(root, stageRoot, releaseVersion)
	if err != nil {
		return err
	}
	fmt.Printf("site-build: published generated site and synced release footer %s (%d pages)\n", releaseVersion, footerCount)
	return nil
}

func decodeManualMeta(source []byte) (meta, error) {
	var m meta
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	decoder.KnownFields(true)
	if err := decoder.Decode(&m); err != nil {
		return meta{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return meta{}, fmt.Errorf("multiple YAML documents are not allowed")
		}
		return meta{}, err
	}
	return m, nil
}

func validateManualContract(manualsDir string, m meta, strict bool) error {
	languages := make(map[string]struct{}, len(m.Languages))
	for _, lang := range m.Languages {
		if !manualIDPattern.MatchString(lang) {
			return fmt.Errorf("manual metadata contains invalid language ID %q", lang)
		}
		if _, duplicate := languages[lang]; duplicate {
			return fmt.Errorf("manual metadata contains duplicate language %q", lang)
		}
		languages[lang] = struct{}{}
	}
	if _, ok := languages[m.DefaultLanguage]; !ok {
		return fmt.Errorf("default language %q is not declared", m.DefaultLanguage)
	}
	if len(m.Sections) == 0 {
		return fmt.Errorf("manual metadata declares no sections")
	}

	expected := make(map[string]struct{})
	sectionIDs := make(map[string]struct{}, len(m.Sections))
	for _, section := range m.Sections {
		if !manualIDPattern.MatchString(section.ID) {
			return fmt.Errorf("manual metadata contains invalid section ID %q", section.ID)
		}
		if _, duplicate := sectionIDs[section.ID]; duplicate {
			return fmt.Errorf("manual metadata contains duplicate section ID %q", section.ID)
		}
		sectionIDs[section.ID] = struct{}{}
		if strings.TrimSpace(section.Icon) == "" {
			return fmt.Errorf("manual metadata section %q has no icon", section.ID)
		}
		if err := validateLocalizedTitles("section "+section.ID, section.Title, languages); err != nil {
			return err
		}
		if len(section.Pages) == 0 {
			return fmt.Errorf("manual metadata section %q declares no pages", section.ID)
		}
		pageIDs := make(map[string]struct{}, len(section.Pages))
		for _, page := range section.Pages {
			if !manualIDPattern.MatchString(page.ID) {
				return fmt.Errorf("manual metadata section %q contains invalid page ID %q", section.ID, page.ID)
			}
			if _, duplicate := pageIDs[page.ID]; duplicate {
				return fmt.Errorf("manual metadata section %q contains duplicate page ID %q", section.ID, page.ID)
			}
			pageIDs[page.ID] = struct{}{}
			expected[filepath.ToSlash(filepath.Join(section.ID, page.ID+".md"))] = struct{}{}
			if err := validateLocalizedTitles("page "+section.ID+"/"+page.ID, page.Title, languages); err != nil {
				return err
			}
		}
	}
	if !strict {
		return nil
	}

	entries, err := os.ReadDir(manualsDir)
	if err != nil {
		return fmt.Errorf("read manual source directory: %w", err)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("manual source entry %q must not be a symlink", entry.Name())
		}
		if !entry.IsDir() {
			continue
		}
		if _, declared := languages[entry.Name()]; !declared {
			return fmt.Errorf("manual source contains undeclared language directory %q", entry.Name())
		}
	}

	for _, lang := range m.Languages {
		langDir := filepath.Join(manualsDir, lang)
		actual := make(map[string]struct{}, len(expected))
		err := filepath.WalkDir(langDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("manual source %s must not be a symlink", path)
			}
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
				return nil
			}
			rel, relErr := filepath.Rel(langDir, path)
			if relErr != nil {
				return relErr
			}
			actual[filepath.ToSlash(rel)] = struct{}{}
			return nil
		})
		if err != nil {
			return fmt.Errorf("inspect %s manual sources: %w", lang, err)
		}
		for path := range expected {
			if _, ok := actual[path]; !ok {
				return fmt.Errorf("manual page %s is missing for language %s", path, lang)
			}
		}
		for path := range actual {
			if _, ok := expected[path]; !ok {
				return fmt.Errorf("manual page %s for language %s is not declared in _meta.yaml", path, lang)
			}
		}
	}
	return nil
}

func validateLocalizedTitles(owner string, titles map[string]string, languages map[string]struct{}) error {
	for lang := range languages {
		if strings.TrimSpace(titles[lang]) == "" {
			return fmt.Errorf("manual metadata %s has no %s title", owner, lang)
		}
	}
	for lang := range titles {
		if _, declared := languages[lang]; !declared {
			return fmt.Errorf("manual metadata %s has a title for undeclared language %q", owner, lang)
		}
	}
	return nil
}

// findRoot walks up from the working directory to the repository root.
func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "docs", "user-manuals", "_meta.yaml")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate docs/user-manuals/_meta.yaml from working directory")
		}
		dir = parent
	}
}

func newMarkdown() goldmark.Markdown {
	return goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
		goldmark.WithRendererOptions(gmhtml.WithUnsafe()),
	)
}

// splitFrontMatter separates an optional leading YAML front-matter block from
// the Markdown body. The closing delimiter must be a line containing exactly
// "---" (ignoring surrounding whitespace) — a substring match would also
// accept a longer dash rule (e.g. "----------") or a line like "---some-text"
// that merely starts with the same three characters, truncating the front
// matter prematurely.
func splitFrontMatter(b []byte) (frontMatter, string, error) {
	var fm frontMatter
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return fm, s, nil
	}
	lines := strings.Split(s, "\n")
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return fm, s, nil
	}
	header := strings.Join(lines[1:end], "\n")
	body := strings.Join(lines[end+1:], "\n")
	body = strings.TrimPrefix(body, "\n")
	if err := yaml.Unmarshal([]byte(header), &fm); err != nil {
		return fm, "", err
	}
	return fm, body, nil
}

// renderMarkdown converts Markdown to HTML, supporting fenced callout blocks of
// the form:
//
//	:::tip
//	Body markdown.
//	:::
//
// Supported types: tip, note, warn, danger. Labels are localized per language.
func renderMarkdown(md goldmark.Markdown, source, lang string) (string, error) {
	lines := strings.Split(source, "\n")
	out := make([]string, 0, len(lines))
	callouts := map[string]string{}
	n := 0

	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, ":::") && len(trimmed) > 3 {
			typ := strings.ToLower(strings.TrimSpace(trimmed[3:]))
			startLine := i + 1 // 1-based, for error messages
			var body []string
			i++
			for i < len(lines) && strings.TrimSpace(lines[i]) != ":::" {
				body = append(body, lines[i])
				i++
			}
			if i >= len(lines) {
				// Ran off the end of the page without finding the closing
				// fence: failing loudly here beats silently absorbing the
				// rest of the page into one callout box on the live site.
				return "", fmt.Errorf("unterminated ::: callout (type %q) opened at line %d: no closing ::: found", typ, startLine)
			}
			inner, err := toHTML(md, strings.Join(body, "\n"))
			if err != nil {
				return "", err
			}
			placeholder := fmt.Sprintf("@@LWCALLOUT_%d@@", n)
			callouts[placeholder] = fmt.Sprintf(
				`<div class="callout callout-%s"><div class="callout-label">%s</div><div class="callout-body">%s</div></div>`,
				calloutType(typ), calloutLabel(typ, lang), inner,
			)
			out = append(out, "", placeholder, "")
			n++
			continue
		}
		out = append(out, lines[i])
	}

	rendered, err := toHTML(md, strings.Join(out, "\n"))
	if err != nil {
		return "", err
	}
	for ph, h := range callouts {
		rendered = strings.ReplaceAll(rendered, "<p>"+ph+"</p>", h)
	}
	return rendered, nil
}

func toHTML(md goldmark.Markdown, source string) (string, error) {
	var buf strings.Builder
	if err := md.Convert([]byte(source), &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func calloutType(typ string) string {
	switch typ {
	case "tip", "note", "warn", "danger":
		return typ
	case "warning":
		return "warn"
	case "info":
		return "note"
	default:
		return "note"
	}
}

func calloutLabel(typ, lang string) string {
	t := calloutType(typ)
	labels := map[string]map[string]string{
		"en": {"tip": "Tip", "note": "Note", "warn": "Warning", "danger": "Danger"},
		"tr": {"tip": "İpucu", "note": "Not", "warn": "Uyarı", "danger": "Tehlike"},
	}
	if m, ok := labels[lang]; ok {
		if l, ok := m[t]; ok {
			return l
		}
	}
	return labels["en"][t]
}

// writeJSON marshals v and writes it as a JavaScript assignment.
func writeJSON(path, assign string, v any, indent bool) error {
	var (
		data []byte
		err  error
	)
	if indent {
		data, err = json.MarshalIndent(v, "", "  ")
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	content := fmt.Sprintf("// Generated by tools/site-build. Do not edit by hand.\n%s = %s;\n", assign, data)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

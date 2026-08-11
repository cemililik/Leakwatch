package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

func TestPublishedMarkdownLinksResolve(t *testing.T) {
	root, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := publishedMarkdownPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("publishedMarkdownPaths() returned no documents")
	}
	validator := newMarkdownLinkValidator(root)

	for _, path := range paths {
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			continue
		}
		for _, linkErr := range validator.validate(path, source) {
			t.Error(linkErr)
		}
	}
}

func TestValidateMarkdownLinks_CommonMarkMatrix(t *testing.T) {
	root := t.TempDir()
	docsDir := filepath.Join(root, "docs")
	if err := os.MkdirAll(filepath.Join(docsDir, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"target.md", "image.png", "dir/space name.md", "dir/paren(name).md"} {
		path := filepath.Join(docsDir, filepath.FromSlash(name))
		content := []byte("ok\n")
		if name == "target.md" {
			content = []byte("# Section\n")
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(docsDir, "source.md")

	valid := strings.Join([]string{
		"# Local",
		"",
		"[inline](target.md \"title\")",
		"[reference][target]",
		"![image](image.png)",
		"[angle](<dir/space name.md>)",
		"[parentheses](dir/paren(name).md)",
		"[fragment](target.md#section)",
		"[root relative](/docs/target.md)",
		"[multiline](",
		"  target.md",
		")",
		"[external](https://example.com/path)",
		"[anchor](#local)",
		"[site route](#/getting-started/installation)",
		"",
		"[target]: target.md",
	}, "\n")
	if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if errs := validateMarkdownLinks(root, path, []byte(valid)); len(errs) != 0 {
		t.Fatalf("valid CommonMark links returned errors: %v", errs)
	}

	invalid := strings.Join([]string{
		"[missing inline](missing.md)",
		"[missing reference][missing]",
		"[repository escape](../../outside.md)",
		"[missing fragment](target.md#absent)",
		"",
		"[missing]: absent.md",
	}, "\n")
	if errs := validateMarkdownLinks(root, path, []byte(invalid)); len(errs) != 4 {
		t.Fatalf("invalid CommonMark links returned %d errors, want 4: %v", len(errs), errs)
	}
}

func TestPublishedMarkdownPaths_IgnoresNonDocumentationSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Docs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "asset.txt")
	if err := os.WriteFile(target, []byte("asset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "asset-link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	paths, err := publishedMarkdownPaths(root)
	if err != nil {
		t.Fatalf("non-documentation symlink caused false positive: %v", err)
	}
	if len(paths) != 1 || filepath.Base(paths[0]) != "README.md" {
		t.Fatalf("publishedMarkdownPaths() = %v, want README.md only", paths)
	}
	if err := os.Symlink(filepath.Join(root, "README.md"), filepath.Join(root, "linked.md")); err != nil {
		t.Skipf("Markdown symlink unavailable: %v", err)
	}
	if _, err := publishedMarkdownPaths(root); err == nil {
		t.Fatal("publishedMarkdownPaths() accepted a Markdown symlink")
	}
}

func publishedMarkdownPaths(root string) ([]string, error) {
	skipDirs := map[string]struct{}{
		".git": {}, "node_modules": {}, "vendor": {}, "dist": {}, "review": {},
	}
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
				return fmt.Errorf("documentation path must not be a symlink: %s", path)
			}
			return nil
		}
		if entry.IsDir() {
			if path != root {
				if _, skip := skipDirs[entry.Name()]; skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".md") {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}

type markdownLinkValidator struct {
	root        string
	anchorCache map[string]map[string]struct{}
}

var rawHTMLAnchorPattern = regexp.MustCompile(`(?i)(?:id|name)[[:space:]]*=[[:space:]]*["']([^"']+)["']`)

func newMarkdownLinkValidator(root string) *markdownLinkValidator {
	return &markdownLinkValidator{root: filepath.Clean(root), anchorCache: make(map[string]map[string]struct{})}
}

func validateMarkdownLinks(root, sourcePath string, source []byte) []error {
	return newMarkdownLinkValidator(root).validate(sourcePath, source)
}

func (v *markdownLinkValidator) validate(sourcePath string, source []byte) []error {
	document := newMarkdown().Parser().Parse(text.NewReader(source))
	v.anchorCache[filepath.Clean(sourcePath)] = markdownAnchors(document, source)
	var errors []error
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var destination []byte
		switch n := node.(type) {
		case *ast.Link:
			destination = n.Destination
		case *ast.Image:
			destination = n.Destination
		default:
			return ast.WalkContinue, nil
		}
		if err := v.validateDestination(sourcePath, string(destination)); err != nil {
			errors = append(errors, err)
		}
		return ast.WalkContinue, nil
	})
	return errors
}

func (v *markdownLinkValidator) validateDestination(sourcePath, rawDestination string) error {
	destination := strings.TrimSpace(rawDestination)
	if destination == "" || strings.HasPrefix(destination, "//") || strings.HasPrefix(destination, "#/") {
		return nil
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		return fmt.Errorf("%s has malformed link %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	if parsed.Scheme != "" {
		return nil
	}
	target, err := v.resolveLocalLinkTarget(sourcePath, rawDestination, parsed)
	if err != nil {
		return err
	}
	if err := v.validateLocalLinkTarget(sourcePath, rawDestination, target); err != nil {
		return err
	}
	return v.validateMarkdownFragment(sourcePath, rawDestination, target, parsed.Fragment)
}

func (v *markdownLinkValidator) resolveLocalLinkTarget(sourcePath, rawDestination string, parsed *url.URL) (string, error) {
	decodedPath, err := url.PathUnescape(parsed.Path)
	if err != nil {
		return "", fmt.Errorf("%s has malformed escaped link %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	var target string
	if decodedPath == "" {
		target = sourcePath
	} else if strings.HasPrefix(decodedPath, "/") {
		target = filepath.Join(v.root, filepath.FromSlash(strings.TrimPrefix(decodedPath, "/")))
	} else {
		target = filepath.Join(filepath.Dir(sourcePath), filepath.FromSlash(decodedPath))
	}
	target = filepath.Clean(target)
	rel, err := filepath.Rel(v.root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s has link %q outside the repository", filepath.ToSlash(sourcePath), rawDestination)
	}
	return target, nil
}

func (v *markdownLinkValidator) validateLocalLinkTarget(sourcePath, rawDestination, target string) error {
	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf("%s has unresolved link %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s links to symlink %q; documentation targets must be repository-owned regular paths", filepath.ToSlash(sourcePath), rawDestination)
	}
	return nil
}

func (v *markdownLinkValidator) validateMarkdownFragment(sourcePath, rawDestination, target, rawFragment string) error {
	if rawFragment == "" || !strings.EqualFold(filepath.Ext(target), ".md") {
		return nil
	}
	fragment, err := url.PathUnescape(rawFragment)
	if err != nil {
		return fmt.Errorf("%s has malformed escaped fragment in %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	anchors, err := v.anchorsFor(target)
	if err != nil {
		return fmt.Errorf("%s cannot inspect fragment target %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	if _, exists := anchors[fragment]; !exists {
		return fmt.Errorf("%s has unresolved fragment %q in %s", filepath.ToSlash(sourcePath), fragment, filepath.ToSlash(target))
	}
	return nil
}

func (v *markdownLinkValidator) anchorsFor(path string) (map[string]struct{}, error) {
	path = filepath.Clean(path)
	if anchors, ok := v.anchorCache[path]; ok {
		return anchors, nil
	}
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	document := newMarkdown().Parser().Parse(text.NewReader(source))
	anchors := markdownAnchors(document, source)
	v.anchorCache[path] = anchors
	return anchors, nil
}

func markdownAnchors(document ast.Node, source []byte) map[string]struct{} {
	anchors := make(map[string]struct{})
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if heading, ok := node.(*ast.Heading); ok {
			if value, exists := heading.AttributeString("id"); exists {
				switch id := value.(type) {
				case []byte:
					anchors[string(id)] = struct{}{}
				case string:
					anchors[id] = struct{}{}
				}
			}
		}
		var raw []byte
		switch html := node.(type) {
		case *ast.RawHTML:
			raw = html.Segments.Value(source)
		case *ast.HTMLBlock:
			raw = html.Text(source)
		}
		for _, match := range rawHTMLAnchorPattern.FindAllSubmatch(raw, -1) {
			anchors[string(match[1])] = struct{}{}
		}
		return ast.WalkContinue, nil
	})
	return anchors
}

package main

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
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

	for _, path := range paths {
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			continue
		}
		for _, linkErr := range validateMarkdownLinks(root, path, source) {
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
		if err := os.WriteFile(path, []byte("ok\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(docsDir, "source.md")

	valid := strings.Join([]string{
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
		"",
		"[target]: target.md",
	}, "\n")
	if errs := validateMarkdownLinks(root, path, []byte(valid)); len(errs) != 0 {
		t.Fatalf("valid CommonMark links returned errors: %v", errs)
	}

	invalid := strings.Join([]string{
		"[missing inline](missing.md)",
		"[missing reference][missing]",
		"[repository escape](../../outside.md)",
		"",
		"[missing]: absent.md",
	}, "\n")
	if errs := validateMarkdownLinks(root, path, []byte(invalid)); len(errs) != 3 {
		t.Fatalf("invalid CommonMark links returned %d errors, want 3: %v", len(errs), errs)
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
			return fmt.Errorf("documentation path must not be a symlink: %s", path)
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

func validateMarkdownLinks(root, sourcePath string, source []byte) []error {
	document := newMarkdown().Parser().Parse(text.NewReader(source))
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
		if err := validateMarkdownDestination(root, sourcePath, string(destination)); err != nil {
			errors = append(errors, err)
		}
		return ast.WalkContinue, nil
	})
	return errors
}

func validateMarkdownDestination(root, sourcePath, rawDestination string) error {
	destination := strings.TrimSpace(rawDestination)
	if destination == "" || strings.HasPrefix(destination, "#") || strings.HasPrefix(destination, "//") {
		return nil
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		return fmt.Errorf("%s has malformed link %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	if parsed.Scheme != "" {
		return nil
	}
	decodedPath, err := url.PathUnescape(parsed.Path)
	if err != nil {
		return fmt.Errorf("%s has malformed escaped link %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	if decodedPath == "" {
		return nil
	}
	var target string
	if strings.HasPrefix(decodedPath, "/") {
		target = filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(decodedPath, "/")))
	} else {
		target = filepath.Join(filepath.Dir(sourcePath), filepath.FromSlash(decodedPath))
	}
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s has link %q outside the repository", filepath.ToSlash(sourcePath), rawDestination)
	}
	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Errorf("%s has unresolved link %q: %w", filepath.ToSlash(sourcePath), rawDestination, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s links to symlink %q; documentation targets must be repository-owned regular paths", filepath.ToSlash(sourcePath), rawDestination)
	}
	return nil
}

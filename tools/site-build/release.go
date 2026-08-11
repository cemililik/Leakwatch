package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	releaseVersionConstant = "ReleaseVersion"
	releaseFooterOpen      = `<span class="mono-label" data-release-version>`
	releaseFooterText      = ` · concept: redacted`
)

var stableReleasePattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// readReleaseVersion reads the canonical stable version without importing the
// parent Go module (tools/site-build intentionally has its own module). Keeping
// the value as a string literal also makes unsupported computed metadata fail
// closed instead of silently generating stale site content.
func readReleaseVersion(root string) (string, error) {
	path := filepath.Join(root, "internal", "meta", "release.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return "", fmt.Errorf("parse release metadata: %w", err)
	}

	var found string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			values, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range values.Names {
				if name.Name != releaseVersionConstant {
					continue
				}
				if found != "" {
					return "", fmt.Errorf("%s is declared more than once", releaseVersionConstant)
				}
				if i >= len(values.Values) {
					return "", fmt.Errorf("%s must have an explicit string literal", releaseVersionConstant)
				}
				literal, ok := values.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return "", fmt.Errorf("%s must be a string literal", releaseVersionConstant)
				}
				version, err := strconv.Unquote(literal.Value)
				if err != nil {
					return "", fmt.Errorf("decode %s: %w", releaseVersionConstant, err)
				}
				if !stableReleasePattern.MatchString(version) {
					return "", fmt.Errorf("%s %q is not a stable semantic version", releaseVersionConstant, version)
				}
				found = version
			}
		}
	}
	if found == "" {
		return "", fmt.Errorf("%s not found in %s", releaseVersionConstant, path)
	}
	return found, nil
}

type sitePageUpdate struct {
	path    string
	content []byte
	mode    os.FileMode
}

// syncSiteReleaseVersion validates every top-level site page before writing
// any of them, then atomically replaces each stale page. Requiring the marker
// on every page prevents a removed footer from silently escaping the canonical
// metadata pipeline.
func syncSiteReleaseVersion(root, version string) (int, error) {
	updates, pageCount, err := collectSiteReleaseUpdates(root, version)
	if err != nil {
		return 0, err
	}
	if err := applySiteReleaseUpdates(updates); err != nil {
		return 0, err
	}
	return pageCount, nil
}

func collectSiteReleaseUpdates(root, version string) ([]sitePageUpdate, int, error) {
	if !stableReleasePattern.MatchString(version) {
		return nil, 0, fmt.Errorf("refuse unsafe release version %q", version)
	}

	siteDir := filepath.Join(root, "site")
	if err := validateDirectoryTree(siteDir, siteDir); err != nil {
		return nil, 0, fmt.Errorf("inspect site directory: %w", err)
	}
	pages, err := filepath.Glob(filepath.Join(siteDir, "*.html"))
	if err != nil {
		return nil, 0, fmt.Errorf("find site pages: %w", err)
	}
	if len(pages) == 0 {
		return nil, 0, fmt.Errorf("no top-level site HTML pages found")
	}

	updates := make([]sitePageUpdate, 0, len(pages))
	for _, path := range pages {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, 0, fmt.Errorf("inspect %s: %w", filepath.Base(path), err)
		}
		if !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("site page %s must be a regular file", filepath.Base(path))
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", filepath.Base(path), err)
		}
		updated, err := replaceReleaseFooter(content, version)
		if err != nil {
			return nil, 0, fmt.Errorf("release footer %s: %w", filepath.Base(path), err)
		}
		if bytes.Equal(content, updated) {
			continue
		}
		updates = append(updates, sitePageUpdate{path: path, content: updated, mode: info.Mode().Perm()})
	}

	return updates, len(pages), nil
}

func applySiteReleaseUpdates(updates []sitePageUpdate) error {
	for _, update := range updates {
		if err := writeFileAtomic(update.path, update.content, update.mode); err != nil {
			return fmt.Errorf("write %s: %w", filepath.Base(update.path), err)
		}
	}
	return nil
}

func replaceReleaseFooter(content []byte, version string) ([]byte, error) {
	text := string(content)
	markerCount := strings.Count(text, releaseFooterOpen)
	if markerCount == 0 {
		return nil, fmt.Errorf("missing data-release-version marker")
	}
	if markerCount != 1 {
		return nil, fmt.Errorf("expected one data-release-version marker, found %d", markerCount)
	}
	footerTextCount := strings.Count(text, "concept: redacted")
	if footerTextCount > 1 {
		return nil, fmt.Errorf("expected at most one release footer text, found %d", footerTextCount)
	}

	start := strings.Index(text, releaseFooterOpen)
	bodyStart := start + len(releaseFooterOpen)
	closeOffset := strings.Index(text[bodyStart:], "</span>")
	if closeOffset < 0 {
		return nil, fmt.Errorf("marked release footer has no closing span")
	}
	close := bodyStart + closeOffset
	if strings.ContainsAny(text[bodyStart:close], "<>") {
		return nil, fmt.Errorf("marked release footer body must be plain text")
	}
	if footerTextCount == 1 && !strings.Contains(text[bodyStart:close], "concept: redacted") {
		return nil, fmt.Errorf("release footer text exists outside the marked span")
	}
	wanted := text[:bodyStart] + version + releaseFooterText + text[close:]
	return []byte(wanted), nil
}

func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode.Perm()); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

// commitStagedSite validates the release footer before publishing any staged
// JavaScript. All parsing/rendering/detector work therefore completes outside
// the committed site tree, and a late validation error leaves it untouched.
func commitStagedSite(root, stageRoot, version string) (int, error) {
	updates, pageCount, err := collectSiteReleaseUpdates(root, version)
	if err != nil {
		return 0, err
	}
	if err := publishStagedSite(root, stageRoot); err != nil {
		return 0, err
	}
	if err := applySiteReleaseUpdates(updates); err != nil {
		return 0, err
	}
	return pageCount, nil
}

func publishStagedSite(root, stageRoot string) error {
	type publishItem struct {
		target  string
		content []byte
		mode    os.FileMode
	}

	var stagedFiles []string
	err := filepath.WalkDir(stageRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("staged site entry %s must be a regular file", path)
		}
		stagedFiles = append(stagedFiles, path)
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect staged site: %w", err)
	}
	if len(stagedFiles) == 0 {
		return fmt.Errorf("staged site contains no generated files")
	}

	siteDir := filepath.Join(root, "site")
	items := make([]publishItem, 0, len(stagedFiles))
	for _, stagedPath := range stagedFiles {
		rel, err := filepath.Rel(stageRoot, stagedPath)
		if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("resolve staged site path %s", stagedPath)
		}
		target := filepath.Join(siteDir, rel)
		if err := validateDirectoryTree(siteDir, filepath.Dir(target)); err != nil {
			return fmt.Errorf("inspect generated site directory for %s: %w", target, err)
		}

		mode := os.FileMode(0o644)
		info, err := os.Lstat(target)
		switch {
		case err == nil:
			if !info.Mode().IsRegular() {
				return fmt.Errorf("generated site target %s must be a regular file", target)
			}
			mode = info.Mode().Perm()
		case !os.IsNotExist(err):
			return fmt.Errorf("inspect generated site target %s: %w", target, err)
		}
		content, err := os.ReadFile(stagedPath)
		if err != nil {
			return fmt.Errorf("read staged site file %s: %w", stagedPath, err)
		}
		items = append(items, publishItem{target: target, content: content, mode: mode})
	}

	// All staged inputs, target paths, file types, and parent chains are checked
	// before the first committed file is replaced.
	for _, item := range items {
		if err := ensureDirectoryTree(siteDir, filepath.Dir(item.target)); err != nil {
			return fmt.Errorf("create generated site directory for %s: %w", item.target, err)
		}
		if err := writeFileAtomic(item.target, item.content, item.mode); err != nil {
			return fmt.Errorf("publish generated site file %s: %w", item.target, err)
		}
	}
	return nil
}

func validateDirectoryTree(base, target string) error {
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("directory %s escapes base %s", target, base)
	}

	current := base
	parts := []string{}
	if rel != "." {
		parts = strings.Split(rel, string(filepath.Separator))
	}
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			current = filepath.Join(current, parts[i])
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if i == -1 {
				return fmt.Errorf("base directory %s does not exist", base)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s must be a real directory", current)
		}
	}
	return nil
}

func ensureDirectoryTree(base, target string) error {
	if err := validateDirectoryTree(base, target); err != nil {
		return err
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return err
	}
	current := base
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o755); err != nil && !os.IsExist(err) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s must be a real directory", current)
		}
	}
	return nil
}

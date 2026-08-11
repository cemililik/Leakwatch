package main

import (
	"bytes"
	"errors"
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

var (
	stableReleasePattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	replaceSiteFile      = os.Rename
)

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
	if err := applySiteReleaseUpdates(filepath.Join(root, "site"), updates); err != nil {
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

type preparedSiteUpdate struct {
	update          sitePageUpdate
	tempPath        string
	originalContent []byte
	originalMode    os.FileMode
	existed         bool
}

// applySiteReleaseUpdates publishes a set of generated/footer files as one
// recoverable transaction. Every replacement is fully written and fsynced to
// a sibling temporary file before the first target changes. If a later atomic
// replace fails, earlier replacements are restored in reverse order; rollback
// failures are joined into the returned error instead of being hidden.
func applySiteReleaseUpdates(siteDir string, updates []sitePageUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	if err := validateDirectoryTree(siteDir, siteDir); err != nil {
		return fmt.Errorf("inspect site transaction root: %w", err)
	}
	normalized, err := normalizeSiteUpdates(siteDir, updates)
	if err != nil {
		return err
	}
	createdDirs, err := prepareSiteTargetDirectories(siteDir, normalized)
	if err != nil {
		return err
	}
	prepared, err := prepareSiteUpdates(normalized)
	if err != nil {
		cleanupPreparedSiteUpdates(prepared)
		cleanupCreatedDirectories(createdDirs)
		return err
	}
	if err := publishPreparedSiteUpdates(prepared); err != nil {
		cleanupPreparedSiteUpdates(prepared)
		cleanupCreatedDirectories(createdDirs)
		return err
	}
	return nil
}

func normalizeSiteUpdates(siteDir string, updates []sitePageUpdate) ([]sitePageUpdate, error) {
	seenTargets := make(map[string]struct{}, len(updates))
	normalized := make([]sitePageUpdate, len(updates))
	for index, update := range updates {
		update.path = filepath.Clean(update.path)
		rel, err := filepath.Rel(siteDir, update.path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("site transaction target %s escapes %s", update.path, siteDir)
		}
		if _, duplicate := seenTargets[update.path]; duplicate {
			return nil, fmt.Errorf("site transaction contains duplicate target %s", update.path)
		}
		seenTargets[update.path] = struct{}{}
		normalized[index] = update
	}
	return normalized, nil
}

func prepareSiteTargetDirectories(siteDir string, updates []sitePageUpdate) ([]string, error) {
	var createdDirs []string
	for _, update := range updates {
		created, err := ensureDirectoryTreeTracked(siteDir, filepath.Dir(update.path))
		if err != nil {
			cleanupCreatedDirectories(createdDirs)
			return nil, fmt.Errorf("prepare target directory for %s: %w", update.path, err)
		}
		createdDirs = append(createdDirs, created...)
	}
	return createdDirs, nil
}

func prepareSiteUpdates(updates []sitePageUpdate) ([]preparedSiteUpdate, error) {
	prepared := make([]preparedSiteUpdate, 0, len(updates))
	for _, update := range updates {
		item, err := prepareSiteUpdate(update)
		if err != nil {
			return prepared, err
		}
		prepared = append(prepared, item)
	}
	return prepared, nil
}

func prepareSiteUpdate(update sitePageUpdate) (preparedSiteUpdate, error) {
	item := preparedSiteUpdate{update: update}
	info, err := os.Lstat(update.path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return item, fmt.Errorf("site transaction target %s must be a regular file", update.path)
		}
		item.originalContent, err = os.ReadFile(update.path)
		if err != nil {
			return item, fmt.Errorf("snapshot site target %s: %w", update.path, err)
		}
		item.originalMode, item.existed = info.Mode().Perm(), true
	} else if !os.IsNotExist(err) {
		return item, fmt.Errorf("inspect site target %s: %w", update.path, err)
	}
	item.tempPath, err = prepareSiblingFile(update.path, update.content, update.mode)
	if err != nil {
		return item, fmt.Errorf("stage site target %s: %w", update.path, err)
	}
	return item, nil
}

func publishPreparedSiteUpdates(prepared []preparedSiteUpdate) error {
	for index := range prepared {
		item := &prepared[index]
		if err := replaceSiteFile(item.tempPath, item.update.path); err != nil {
			publishErr := fmt.Errorf("publish site target %s: %w", item.update.path, err)
			rollbackErr := rollbackSiteUpdates(prepared[:index])
			return errors.Join(publishErr, rollbackErr)
		}
		item.tempPath = ""
	}
	return nil
}

func cleanupPreparedSiteUpdates(prepared []preparedSiteUpdate) {
	for _, item := range prepared {
		if item.tempPath != "" {
			_ = os.Remove(item.tempPath)
		}
	}
}

func prepareSiblingFile(target string, content []byte, mode os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	failed := true
	defer func() {
		_ = tmp.Close()
		if failed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		return "", err
	}
	if _, err := tmp.Write(content); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	failed = false
	return tmpPath, nil
}

func rollbackSiteUpdates(committed []preparedSiteUpdate) error {
	var rollbackErrors []error
	for index := len(committed) - 1; index >= 0; index-- {
		item := committed[index]
		if item.existed {
			if err := writeFileAtomic(item.update.path, item.originalContent, item.originalMode); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s: %w", item.update.path, err))
			}
			continue
		}
		if err := os.Remove(item.update.path); err != nil && !os.IsNotExist(err) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("remove new target %s: %w", item.update.path, err))
		}
	}
	return errors.Join(rollbackErrors...)
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
	closingSpan := bodyStart + closeOffset
	if strings.ContainsAny(text[bodyStart:closingSpan], "<>") {
		return nil, fmt.Errorf("marked release footer body must be plain text")
	}
	if footerTextCount == 1 && !strings.Contains(text[bodyStart:closingSpan], "concept: redacted") {
		return nil, fmt.Errorf("release footer text exists outside the marked span")
	}
	wanted := text[:bodyStart] + version + releaseFooterText + text[closingSpan:]
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
	footerUpdates, pageCount, err := collectSiteReleaseUpdates(root, version)
	if err != nil {
		return 0, err
	}
	generatedUpdates, err := collectStagedSiteUpdates(root, stageRoot)
	if err != nil {
		return 0, err
	}
	updates := append(generatedUpdates, footerUpdates...)
	if err := applySiteReleaseUpdates(filepath.Join(root, "site"), updates); err != nil {
		return 0, err
	}
	return pageCount, nil
}

func publishStagedSite(root, stageRoot string) error {
	updates, err := collectStagedSiteUpdates(root, stageRoot)
	if err != nil {
		return err
	}
	return applySiteReleaseUpdates(filepath.Join(root, "site"), updates)
}

func collectStagedSiteUpdates(root, stageRoot string) ([]sitePageUpdate, error) {
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
		return nil, fmt.Errorf("inspect staged site: %w", err)
	}
	if len(stagedFiles) == 0 {
		return nil, fmt.Errorf("staged site contains no generated files")
	}

	siteDir := filepath.Join(root, "site")
	updates := make([]sitePageUpdate, 0, len(stagedFiles))
	for _, stagedPath := range stagedFiles {
		rel, err := filepath.Rel(stageRoot, stagedPath)
		if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("resolve staged site path %s", stagedPath)
		}
		target := filepath.Join(siteDir, rel)
		if err := validateDirectoryTree(siteDir, filepath.Dir(target)); err != nil {
			return nil, fmt.Errorf("inspect generated site directory for %s: %w", target, err)
		}

		mode := os.FileMode(0o644)
		info, err := os.Lstat(target)
		switch {
		case err == nil:
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("generated site target %s must be a regular file", target)
			}
			mode = info.Mode().Perm()
		case !os.IsNotExist(err):
			return nil, fmt.Errorf("inspect generated site target %s: %w", target, err)
		}
		content, err := os.ReadFile(stagedPath)
		if err != nil {
			return nil, fmt.Errorf("read staged site file %s: %w", stagedPath, err)
		}
		updates = append(updates, sitePageUpdate{path: target, content: content, mode: mode})
	}
	return updates, nil
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

func ensureDirectoryTreeTracked(base, target string) ([]string, error) {
	if err := validateDirectoryTree(base, target); err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return nil, err
	}
	current := base
	if rel == "." {
		return nil, nil
	}
	var created []string
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o755); err == nil {
			created = append(created, current)
		} else if !os.IsExist(err) {
			cleanupCreatedDirectories(created)
			return nil, err
		}
		info, err := os.Lstat(current)
		if err != nil {
			cleanupCreatedDirectories(created)
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			cleanupCreatedDirectories(created)
			return nil, fmt.Errorf("%s must be a real directory", current)
		}
	}
	return created, nil
}

func cleanupCreatedDirectories(paths []string) {
	for index := len(paths) - 1; index >= 0; index-- {
		_ = os.Remove(paths[index])
	}
}

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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

// syncSiteReleaseVersion rewrites every marked top-level site page. Any page
// carrying the release-footer text without the marker fails the build, so a
// newly copied/manual footer cannot escape the canonical metadata pipeline.
func syncSiteReleaseVersion(root, version string) (int, error) {
	if !stableReleasePattern.MatchString(version) {
		return 0, fmt.Errorf("refuse unsafe release version %q", version)
	}

	pages, err := filepath.Glob(filepath.Join(root, "site", "*.html"))
	if err != nil {
		return 0, fmt.Errorf("find site pages: %w", err)
	}
	if len(pages) == 0 {
		return 0, fmt.Errorf("no top-level site HTML pages found")
	}

	marked := 0
	for _, path := range pages {
		content, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", filepath.Base(path), err)
		}
		updated, hasFooter, err := replaceReleaseFooter(content, version)
		if err != nil {
			return 0, fmt.Errorf("release footer %s: %w", filepath.Base(path), err)
		}
		if !hasFooter {
			continue
		}
		marked++
		if bytes.Equal(content, updated) {
			continue
		}
		if err := os.WriteFile(path, updated, 0o644); err != nil {
			return 0, fmt.Errorf("write %s: %w", filepath.Base(path), err)
		}
	}
	if marked == 0 {
		return 0, fmt.Errorf("no release footer markers found in site HTML pages")
	}
	return marked, nil
}

func replaceReleaseFooter(content []byte, version string) ([]byte, bool, error) {
	text := string(content)
	markerCount := strings.Count(text, releaseFooterOpen)
	if markerCount == 0 {
		if strings.Contains(text, "concept: redacted") {
			return nil, false, fmt.Errorf("footer text exists without data-release-version marker")
		}
		return content, false, nil
	}
	if markerCount != 1 {
		return nil, false, fmt.Errorf("expected one data-release-version marker, found %d", markerCount)
	}
	footerTextCount := strings.Count(text, "concept: redacted")
	if footerTextCount > 1 {
		return nil, false, fmt.Errorf("expected at most one release footer text, found %d", footerTextCount)
	}

	start := strings.Index(text, releaseFooterOpen)
	bodyStart := start + len(releaseFooterOpen)
	closeOffset := strings.Index(text[bodyStart:], "</span>")
	if closeOffset < 0 {
		return nil, false, fmt.Errorf("marked release footer has no closing span")
	}
	close := bodyStart + closeOffset
	if strings.ContainsAny(text[bodyStart:close], "<>") {
		return nil, false, fmt.Errorf("marked release footer body must be plain text")
	}
	if footerTextCount == 1 && !strings.Contains(text[bodyStart:close], "concept: redacted") {
		return nil, false, fmt.Errorf("release footer text exists outside the marked span")
	}
	wanted := text[:bodyStart] + version + releaseFooterText + text[close:]
	return []byte(wanted), true, nil
}

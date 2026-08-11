package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitFrontMatter(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantTitle   string
		wantBodyHas string
		wantErr     bool
	}{
		{
			name:        "no front matter",
			input:       "# Just a heading\n",
			wantTitle:   "",
			wantBodyHas: "# Just a heading",
		},
		{
			name: "well-formed front matter",
			input: "---\n" +
				"title: Hello\n" +
				"description: World\n" +
				"---\n" +
				"# Body\n",
			wantTitle:   "Hello",
			wantBodyHas: "# Body",
		},
		{
			name: "line merely starting with --- is not treated as the closing delimiter",
			input: "---\n" +
				"title: Hello\n" +
				"note: \"----------\"\n" +
				"---\n" +
				"# Body\n",
			wantTitle:   "Hello",
			wantBodyHas: "# Body",
		},
		{
			name: "body line starting with --- is not mistaken for the delimiter",
			input: "---\n" +
				"title: Hello\n" +
				"---\n" +
				"---some-dashed-heading\n" +
				"# Body\n",
			wantTitle:   "Hello",
			wantBodyHas: "---some-dashed-heading",
		},
		{
			name: "unterminated front matter falls back to raw body",
			input: "---\n" +
				"title: Hello\n" +
				"no closing fence here\n",
			wantTitle:   "",
			wantBodyHas: "---",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, body, err := splitFrontMatter([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("splitFrontMatter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if fm.Title != tt.wantTitle {
				t.Errorf("title = %q, want %q", fm.Title, tt.wantTitle)
			}
			if !strings.Contains(body, tt.wantBodyHas) {
				t.Errorf("body = %q, want it to contain %q", body, tt.wantBodyHas)
			}
		})
	}
}

func TestRenderMarkdown_UnterminatedCalloutFailsLoudly(t *testing.T) {
	md := newMarkdown()
	source := "Intro paragraph.\n\n:::tip\nThis callout is never closed.\n\n## Rest of the page\n\nMore content that must not be silently absorbed.\n"
	_, err := renderMarkdown(md, source, "en")
	if err == nil {
		t.Fatal("expected an error for an unterminated ::: callout, got nil")
	}
	if !strings.Contains(err.Error(), "unterminated") {
		t.Errorf("error = %v, want it to mention 'unterminated'", err)
	}
}

func TestRenderMarkdown_TerminatedCalloutRendersNormally(t *testing.T) {
	md := newMarkdown()
	source := ":::tip\nBody text.\n:::\n\n## After\n"
	out, err := renderMarkdown(md, source, "en")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "callout-tip") {
		t.Errorf("output missing rendered callout: %q", out)
	}
	if !strings.Contains(out, "After") {
		t.Errorf("output missing content after the callout: %q", out)
	}
}

func TestValidateManualContract_FailsClosedOnMetadataAndSourceDrift(t *testing.T) {
	validMeta := func() meta {
		return meta{
			Languages:       []string{"en", "tr"},
			DefaultLanguage: "en",
			Sections: []metaSection{{
				ID:    "getting-started",
				Icon:  "rocket",
				Title: map[string]string{"en": "Getting Started", "tr": "Başlarken"},
				Pages: []metaPage{{
					ID:    "introduction",
					Title: map[string]string{"en": "Introduction", "tr": "Tanıtım"},
				}},
			}},
		}
	}
	writePage := func(t *testing.T, root, lang, relative string) {
		t.Helper()
		path := filepath.Join(root, lang, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("# page\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	validSources := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		for _, lang := range []string{"en", "tr"} {
			writePage(t, root, lang, "getting-started/introduction.md")
		}
		return root
	}

	t.Run("valid exact source set", func(t *testing.T) {
		requireNoError(t, validateManualContract(validSources(t), validMeta(), true))
	})

	tests := []struct {
		name   string
		mutate func(t *testing.T, root string, m *meta)
	}{
		{
			name: "English-only orphan",
			mutate: func(t *testing.T, root string, _ *meta) {
				writePage(t, root, "en", "getting-started/orphan.md")
			},
		},
		{
			name: "orphan in every language",
			mutate: func(t *testing.T, root string, _ *meta) {
				writePage(t, root, "en", "getting-started/orphan.md")
				writePage(t, root, "tr", "getting-started/orphan.md")
			},
		},
		{
			name: "duplicate page ID",
			mutate: func(_ *testing.T, _ string, m *meta) {
				m.Sections[0].Pages = append(m.Sections[0].Pages, m.Sections[0].Pages[0])
			},
		},
		{
			name: "duplicate section ID",
			mutate: func(_ *testing.T, _ string, m *meta) {
				m.Sections = append(m.Sections, m.Sections[0])
			},
		},
		{
			name: "duplicate language ID",
			mutate: func(_ *testing.T, _ string, m *meta) {
				m.Languages = append(m.Languages, "en")
			},
		},
		{
			name: "missing translated title",
			mutate: func(_ *testing.T, _ string, m *meta) {
				delete(m.Sections[0].Pages[0].Title, "tr")
			},
		},
		{
			name: "undeclared translated title",
			mutate: func(_ *testing.T, _ string, m *meta) {
				m.Sections[0].Pages[0].Title["de"] = "Einführung"
			},
		},
		{
			name: "traversing page ID",
			mutate: func(_ *testing.T, _ string, m *meta) {
				m.Sections[0].Pages[0].ID = "../outside"
			},
		},
		{
			name: "missing declared source",
			mutate: func(t *testing.T, root string, _ *meta) {
				if err := os.Remove(filepath.Join(root, "tr", "getting-started", "introduction.md")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "invalid default language",
			mutate: func(_ *testing.T, _ string, m *meta) {
				m.DefaultLanguage = "de"
			},
		},
		{
			name: "undeclared language directory",
			mutate: func(t *testing.T, root string, _ *meta) {
				writePage(t, root, "de", "getting-started/introduction.md")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := validSources(t)
			m := validMeta()
			tc.mutate(t, root, &m)
			if err := validateManualContract(root, m, true); err == nil {
				t.Fatal("validateManualContract() error = nil, want fail-closed error")
			}
		})
	}
}

func TestDecodeManualMeta_FailsClosed(t *testing.T) {
	valid := "languages: [en]\ndefault_language: en\nsections:\n  - id: start\n    icon: rocket\n    title: {en: Start}\n    pages:\n      - id: intro\n        title: {en: Intro}\n"
	if _, err := decodeManualMeta([]byte(valid)); err != nil {
		t.Fatalf("decodeManualMeta(valid) error = %v", err)
	}
	for name, source := range map[string]string{
		"unknown field":      strings.Replace(valid, "default_language:", "default_languag:", 1),
		"multiple documents": valid + "---\nlanguages: [tr]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeManualMeta([]byte(source)); err == nil {
				t.Fatal("decodeManualMeta() error = nil, want fail-closed error")
			}
		})
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadReleaseVersion(t *testing.T) {
	root := t.TempDir()
	metaDir := filepath.Join(root, "internal", "meta")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(metaDir, "release.go")
	if err := os.WriteFile(path, []byte("package meta\nconst ReleaseVersion = \"v2.3.4\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := readReleaseVersion(root)
	if err != nil {
		t.Fatalf("readReleaseVersion() error = %v", err)
	}
	if got != "v2.3.4" {
		t.Fatalf("readReleaseVersion() = %q, want v2.3.4", got)
	}
}

func TestReadReleaseVersion_FailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "missing", source: "package meta\nconst Other = \"v1.2.3\"\n"},
		{name: "computed", source: "package meta\nconst Prefix = \"v\"\nconst ReleaseVersion = Prefix + \"1.2.3\"\n"},
		{name: "prerelease", source: "package meta\nconst ReleaseVersion = \"v1.2.3-rc.1\"\n"},
		{name: "unsafe markup", source: "package meta\nconst ReleaseVersion = \"</span>\"\n"},
		{name: "duplicate", source: "package meta\nconst ReleaseVersion = \"v1.2.3\"\nconst ReleaseVersion = \"v1.2.4\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			metaDir := filepath.Join(root, "internal", "meta")
			if err := os.MkdirAll(metaDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(metaDir, "release.go"), []byte(tt.source), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := readReleaseVersion(root); err == nil {
				t.Fatal("readReleaseVersion() error = nil, want fail-closed error")
			}
		})
	}
}

func TestReplaceReleaseFooter(t *testing.T) {
	input := []byte(`<footer><span class="mono-label" data-release-version>v0.9.0 · concept: redacted</span></footer>`)
	want := `<footer><span class="mono-label" data-release-version>v1.7.0 · concept: redacted</span></footer>`
	got, err := replaceReleaseFooter(input, "v1.7.0")
	if err != nil {
		t.Fatalf("replaceReleaseFooter() error = %v", err)
	}
	if string(got) != want {
		t.Fatalf("replaceReleaseFooter() = %q, want %q", got, want)
	}
}

func TestReplaceReleaseFooter_RejectsUnmanagedOrAmbiguousFooter(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "unmanaged", input: `<span class="mono-label">v1.6.0 · concept: redacted</span>`},
		{name: "duplicate", input: releaseFooterOpen + `old</span>` + releaseFooterOpen + `old</span>`},
		{name: "unclosed", input: releaseFooterOpen + `old`},
		{name: "nested markup", input: releaseFooterOpen + `<em>old</em></span>`},
		{name: "extra unmanaged footer", input: releaseFooterOpen + `old · concept: redacted</span><span>concept: redacted</span>`},
		{name: "only unmanaged footer text", input: `<span>concept: redacted</span>` + releaseFooterOpen + `old</span>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := replaceReleaseFooter([]byte(tt.input), "v1.7.0"); err == nil {
				t.Fatal("replaceReleaseFooter() error = nil, want fail-closed error")
			}
		})
	}
}

func TestSyncSiteReleaseVersion_UpdatesEveryMarkedPage(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "site")
	if err := os.MkdirAll(siteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	modes := map[string]os.FileMode{"index.html": 0o600, "docs.html": 0o644}
	for name, mode := range modes {
		content := releaseFooterOpen + "v0.1.0" + releaseFooterText + "</span>"
		if err := os.WriteFile(filepath.Join(siteDir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	count, err := syncSiteReleaseVersion(root, "v1.7.0")
	if err != nil {
		t.Fatalf("syncSiteReleaseVersion() error = %v", err)
	}
	if count != 2 {
		t.Fatalf("syncSiteReleaseVersion() count = %d, want 2", count)
	}
	for name, wantMode := range modes {
		content, err := os.ReadFile(filepath.Join(siteDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "v1.7.0"+releaseFooterText) {
			t.Fatalf("%s was not synchronized: %s", name, content)
		}
		info, err := os.Stat(filepath.Join(siteDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != wantMode {
			t.Fatalf("%s mode = %o, want %o", name, got, wantMode)
		}
	}
}

func TestSyncSiteReleaseVersion_ValidatesAllPagesBeforeWriting(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "site")
	if err := os.MkdirAll(siteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(siteDir, "a-good.html")
	original := releaseFooterOpen + "v0.1.0" + releaseFooterText + "</span>"
	if err := os.WriteFile(goodPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "z-missing-footer.html"), []byte("<main>no footer</main>"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := syncSiteReleaseVersion(root, "v1.7.0"); err == nil {
		t.Fatal("syncSiteReleaseVersion() error = nil, want missing-marker error")
	}
	content, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != original {
		t.Fatalf("earlier page was partially rewritten: got %q, want %q", content, original)
	}
	info, err := os.Stat(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("earlier page mode = %o, want 600", got)
	}
}

func TestCommitStagedSite_LateFooterErrorDoesNotPublishGeneratedFiles(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "site")
	target := filepath.Join(siteDir, "js", "detectors.js")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old generated output"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siteDir, "index.html"), []byte("<main>missing footer</main>"), 0o644); err != nil {
		t.Fatal(err)
	}

	stageRoot := t.TempDir()
	staged := filepath.Join(stageRoot, "js", "detectors.js")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("new generated output"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := commitStagedSite(root, stageRoot, "v1.7.0"); err == nil {
		t.Fatal("commitStagedSite() error = nil, want missing-footer error")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old generated output" {
		t.Fatalf("generated target was partially published: %q", content)
	}
}

func TestCommitStagedSite_ReplaceFailureRollsBackEveryPublishedTarget(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "site")
	jsDir := filepath.Join(siteDir, "js")
	if err := os.MkdirAll(jsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existingPath := filepath.Join(jsDir, "a-existing.js")
	if err := os.WriteFile(existingPath, []byte("old generated output"), 0o600); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(jsDir, "b-new.js")
	footerPath := filepath.Join(siteDir, "index.html")
	originalFooter := releaseFooterOpen + "v0.1.0" + releaseFooterText + "</span>"
	if err := os.WriteFile(footerPath, []byte(originalFooter), 0o640); err != nil {
		t.Fatal(err)
	}

	stageRoot := t.TempDir()
	stagedJS := filepath.Join(stageRoot, "js")
	if err := os.MkdirAll(stagedJS, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagedJS, "a-existing.js"), []byte("new existing output"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagedJS, "b-new.js"), []byte("new file output"), 0o644); err != nil {
		t.Fatal(err)
	}

	originalReplace := replaceSiteFile
	callCount := 0
	replaceSiteFile = func(oldPath, newPath string) error {
		callCount++
		if callCount == 3 {
			return errors.New("injected third replace failure")
		}
		return os.Rename(oldPath, newPath)
	}
	t.Cleanup(func() { replaceSiteFile = originalReplace })

	if _, err := commitStagedSite(root, stageRoot, "v1.7.0"); err == nil {
		t.Fatal("commitStagedSite() error = nil, want injected transaction failure")
	}
	existing, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(existing) != "old generated output" {
		t.Fatalf("existing generated target was not rolled back: %q", existing)
	}
	info, err := os.Stat(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("rolled-back target mode = %o, want 600", got)
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatalf("new target survived transaction rollback: err=%v", err)
	}
	footer, err := os.ReadFile(footerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(footer) != originalFooter {
		t.Fatalf("footer changed after failed transaction: %q", footer)
	}
	for _, pattern := range []string{filepath.Join(jsDir, ".*.tmp-*"), filepath.Join(siteDir, ".*.tmp-*")} {
		matches, globErr := filepath.Glob(pattern)
		if globErr != nil {
			t.Fatal(globErr)
		}
		if len(matches) != 0 {
			t.Fatalf("transaction left temporary files: %v", matches)
		}
	}
}

func TestPublishStagedSite_RejectsSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	siteDir := filepath.Join(root, "site", "js")
	if err := os.MkdirAll(siteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external.txt")
	if err := os.WriteFile(external, []byte("must remain unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(siteDir, "detectors.js")
	if err := os.Symlink(external, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	stageRoot := t.TempDir()
	staged := filepath.Join(stageRoot, "js", "detectors.js")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishStagedSite(root, stageRoot); err == nil {
		t.Fatal("publishStagedSite() error = nil, want symlink rejection")
	}
	content, err := os.ReadFile(external)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "must remain unchanged" {
		t.Fatalf("symlink target was modified: %q", content)
	}
}

func TestPublishStagedSite_RejectsSymlinkParentDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "site"), 0o755); err != nil {
		t.Fatal(err)
	}
	externalDir := filepath.Join(root, "external")
	if err := os.MkdirAll(externalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalDir, filepath.Join(root, "site", "js")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	stageRoot := t.TempDir()
	staged := filepath.Join(stageRoot, "js", "detectors.js")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publishStagedSite(root, stageRoot); err == nil {
		t.Fatal("publishStagedSite() error = nil, want parent symlink rejection")
	}
	if _, err := os.Stat(filepath.Join(externalDir, "detectors.js")); !os.IsNotExist(err) {
		t.Fatalf("external target exists after rejected publish: err=%v", err)
	}
}

package main

import (
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
	got, marked, err := replaceReleaseFooter(input, "v1.7.0")
	if err != nil {
		t.Fatalf("replaceReleaseFooter() error = %v", err)
	}
	if !marked {
		t.Fatal("replaceReleaseFooter() marked = false, want true")
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
			if _, _, err := replaceReleaseFooter([]byte(tt.input), "v1.7.0"); err == nil {
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
	for _, name := range []string{"index.html", "docs.html"} {
		content := releaseFooterOpen + "v0.1.0" + releaseFooterText + "</span>"
		if err := os.WriteFile(filepath.Join(siteDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(siteDir, "no-footer.html"), []byte("<main>ok</main>"), 0o644); err != nil {
		t.Fatal(err)
	}

	count, err := syncSiteReleaseVersion(root, "v1.7.0")
	if err != nil {
		t.Fatalf("syncSiteReleaseVersion() error = %v", err)
	}
	if count != 2 {
		t.Fatalf("syncSiteReleaseVersion() count = %d, want 2", count)
	}
	for _, name := range []string{"index.html", "docs.html"} {
		content, err := os.ReadFile(filepath.Join(siteDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), "v1.7.0"+releaseFooterText) {
			t.Fatalf("%s was not synchronized: %s", name, content)
		}
	}
}

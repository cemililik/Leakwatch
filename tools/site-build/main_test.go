package main

import (
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

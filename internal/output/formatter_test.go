package output

import "testing"

func TestSanitizeForDisplay(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty string",
			in:   "",
			want: "",
		},
		{
			name: "plain ASCII is untouched",
			in:   "config.yaml",
			want: "config.yaml",
		},
		{
			name: "ESC-prefixed ANSI color escape is stripped",
			in:   "\x1b[31mred\x1b[0m",
			want: "[31mred[0m",
		},
		{
			name: "OSC title-bar injection is stripped",
			in:   "\x1b]0;pwned\x07file.go",
			want: "]0;pwnedfile.go",
		},
		{
			name: "embedded newline and tab are stripped",
			in:   "line1\nline2\tcol",
			want: "line1line2col",
		},
		{
			name: "DEL is stripped",
			in:   "a\x7fbc",
			want: "abc",
		},
		{
			name: "C1 control range (as a valid UTF-8 encoded rune) is stripped",
			in:   "a\u009cb",
			want: "ab",
		},
		{
			name: "a lone invalid UTF-8 byte is replaced, not passed through raw",
			in:   "a\xffb",
			want: "a�b",
		},
		{
			name: "Unicode text is preserved",
			in:   "config-é.yaml",
			want: "config-é.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeForDisplay(tt.in)
			if got != tt.want {
				t.Errorf("SanitizeForDisplay(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

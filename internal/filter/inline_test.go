package filter

import (
	"testing"
)

func TestHasInlineIgnore_GenericMarker_ReturnsTrue(t *testing.T) {
	line := `API_KEY = "AKIA1234EXAMPLE567890"  # leakwatch:ignore`
	if !HasInlineIgnore(line) {
		t.Error("expected HasInlineIgnore to return true for generic marker")
	}
}

func TestHasInlineIgnore_NoMarker_ReturnsFalse(t *testing.T) {
	line := `API_KEY = "AKIA1234EXAMPLE567890"  # some other comment`
	if HasInlineIgnore(line) {
		t.Error("expected HasInlineIgnore to return false when no marker present")
	}
}

func TestHasInlineIgnoreForDetector_SpecificDetector_ReturnsTrue(t *testing.T) {
	line := `PASSWORD = "test123"  # leakwatch:ignore:aws-access-key-id`
	if !HasInlineIgnoreForDetector(line, "aws-access-key-id") {
		t.Error("expected true for matching detector ID")
	}
}

func TestHasInlineIgnoreForDetector_GenericMarker_ReturnsTrue(t *testing.T) {
	line := `API_KEY = "AKIA1234EXAMPLE567890"  # leakwatch:ignore`
	if !HasInlineIgnoreForDetector(line, "aws-access-key-id") {
		t.Error("expected true for generic marker regardless of detector ID")
	}
}

func TestHasInlineIgnoreForDetector_DifferentDetector_ReturnsFalse(t *testing.T) {
	line := `PASSWORD = "test123"  # leakwatch:ignore:aws-access-key-id`
	if HasInlineIgnoreForDetector(line, "github-token") {
		t.Error("expected false for non-matching detector ID")
	}
}

func TestHasInlineIgnoreForDetector_NoMarker_ReturnsFalse(t *testing.T) {
	line := `PASSWORD = "test123"  # safe value`
	if HasInlineIgnoreForDetector(line, "aws-access-key-id") {
		t.Error("expected false when no ignore marker present")
	}
}

func TestHasInlineIgnoreForDetector_PrefixDetectorID_DoesNotFalseMatch(t *testing.T) {
	// Regression test: a short detectorID ("aws") that is a prefix of a longer
	// registered detector's marker ("aws-access-key-id") must not be falsely
	// suppressed by an unbounded substring match against the longer marker.
	line := `PASSWORD = "test123"  # leakwatch:ignore:aws-access-key-id`
	if HasInlineIgnoreForDetector(line, "aws") {
		t.Error("expected false: detectorID 'aws' is a prefix of the marker's 'aws-access-key-id', not an exact match")
	}
}

func TestHasInlineIgnoreForDetector_ExactShortDetectorID_ReturnsTrue(t *testing.T) {
	// The short detector ID must still match correctly when it appears exactly,
	// including when followed by a non-identifier boundary character.
	tests := []struct {
		name string
		line string
	}{
		{"end of line", `PASSWORD = "test123"  # leakwatch:ignore:aws`},
		{"followed by whitespace", `PASSWORD = "test123"  # leakwatch:ignore:aws and more`},
		{"followed by punctuation", `PASSWORD = "test123"  # leakwatch:ignore:aws,other-tag`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !HasInlineIgnoreForDetector(tt.line, "aws") {
				t.Error("expected true for exact detector ID match")
			}
		})
	}
}

func TestHasInlineIgnoreForDetector_LaterExactMatchAfterPrefixCollision_ReturnsTrue(t *testing.T) {
	// A line where the first occurrence of the specific marker is a prefix
	// collision but a second, exact occurrence follows must still match.
	line := `# leakwatch:ignore:aws-access-key-id and also leakwatch:ignore:aws`
	if !HasInlineIgnoreForDetector(line, "aws") {
		t.Error("expected true: an exact marker occurs later in the line")
	}
}

func TestLineHasInlineIgnore(t *testing.T) {
	data := []byte("line1 safe\n" + // line 1
		`API_KEY = "AKIAEXAMPLE" # leakwatch:ignore` + "\n" + // line 2 generic
		`TOKEN = "ghp_x" # leakwatch:ignore:github-token` + "\n" + // line 3 specific
		"line4 safe\n") // line 4

	tests := []struct {
		name       string
		lineNum    int
		detectorID string
		want       bool
	}{
		{"generic marker matches any detector", 2, "aws-access-key-id", true},
		{"specific marker matches its detector", 3, "github-token", true},
		{"specific marker ignores other detectors", 3, "aws-access-key-id", false},
		{"clean line is not ignored", 1, "aws-access-key-id", false},
		{"line zero is never ignored", 0, "aws-access-key-id", false},
		{"negative line is never ignored", -5, "aws-access-key-id", false},
		{"out-of-range line is not ignored", 999, "aws-access-key-id", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LineHasInlineIgnore(data, tt.lineNum, tt.detectorID)
			if got != tt.want {
				t.Errorf("LineHasInlineIgnore(line=%d, %q) = %v, want %v", tt.lineNum, tt.detectorID, got, tt.want)
			}
		})
	}
}

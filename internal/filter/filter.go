// Package filter provides file filtering helpers.
package filter

import (
	"log/slog"
	"path/filepath"
	"strings"
)

const (
	// binaryCheckLen is the number of bytes to inspect for null bytes.
	binaryCheckLen = 8192
)

// defaultBinaryExtensions lists file extensions that are always skipped.
var defaultBinaryExtensions = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".o": true, ".a": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".bmp": true, ".ico": true, ".svg": true, ".webp": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true,
	".rar": true, ".7z": true, ".xz": true,
	".pdf": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
}

// defaultSkipFilenames lists filenames that are always skipped.
// These are auto-generated files that contain hashes/checksums
// which frequently trigger false positives.
var defaultSkipFilenames = map[string]bool{
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
	"composer.lock":     true,
	"Gemfile.lock":      true,
	"Cargo.lock":        true,
	"poetry.lock":       true,
	"go.sum":            true,
	"Pipfile.lock":      true,
}

// IsSkippedFilename checks whether a filename should be skipped.
func IsSkippedFilename(path string) bool {
	return defaultSkipFilenames[filepath.Base(path)]
}

// IsExcludedExtension checks whether a file extension should be excluded.
func IsExcludedExtension(path string, extraExts []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if defaultBinaryExtensions[ext] {
		return true
	}
	for _, e := range extraExts {
		if strings.EqualFold(ext, e) {
			return true
		}
	}
	return false
}

// IsBinaryFile checks whether data appears to be a binary file.
// If a null byte is found within the first 8KB, it is considered binary.
// UTF-16 text (identified by a leading BOM) is exempted from the null-byte
// heuristic: UTF-16 encodes every ASCII character with an accompanying 0x00
// byte, so it would otherwise always be misclassified as binary.
func IsBinaryFile(data []byte) bool {
	if hasUTF16BOM(data) {
		return false
	}
	checkLen := binaryCheckLen
	if len(data) < checkLen {
		checkLen = len(data)
	}
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// hasUTF16BOM reports whether data begins with a UTF-16 byte order mark
// (little-endian 0xFF 0xFE or big-endian 0xFE 0xFF).
func hasUTF16BOM(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return (data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)
}

// MatchesGlob reports whether path matches any of the given glob patterns.
// It supports three pattern styles:
//   - standard filepath.Match globs (e.g. "*.yaml"), tried against both the full
//     path and the base filename so simple patterns match nested files;
//   - "**" (double-star) patterns matched segment-by-segment so "**" spans zero
//     or more directory segments;
//   - gitignore-style directory patterns with a trailing slash (e.g. "build/"),
//     which match every path inside a directory of that name at any depth.
//
// A pattern with invalid glob syntax never matches: filepath.Match's error is
// logged at debug level and treated as a non-match, so one malformed exclude
// pattern cannot abort filtering. (Previously the doc claimed an error was
// returned, which the bool signature could not honor — CFG-m-03.)
func MatchesGlob(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchGlob(pattern, path) {
			return true
		}
		// Also match against the base filename for simple patterns.
		if matchGlob(pattern, filepath.Base(path)) {
			return true
		}
	}
	return false
}

// matchGlob matches a single pattern against a path, supporting ** (double-star)
// and gitignore-style trailing-slash directory patterns. Invalid patterns are
// logged and treated as non-matches.
func matchGlob(pattern, path string) bool {
	// gitignore-style "dir/" matches the whole subtree of a directory named
	// "dir" at any depth (e.g. "build/" matches "build/x" and "src/build/x").
	if trimmed, ok := strings.CutSuffix(pattern, "/"); ok && trimmed != "" && !strings.Contains(trimmed, "**") {
		return matchDirPrefix(trimmed, path)
	}

	// If pattern contains **, use segment-based matching.
	if strings.Contains(pattern, "**") {
		return matchDoubleStar(pattern, path)
	}

	// Normalize both sides to forward slashes: exclude-path patterns are
	// conventionally written with "/" (e.g. "config/secret.pem"), but
	// filepath.Match treats "/" as a literal character rather than an
	// equivalent of the platform separator, so on Windows an un-normalized
	// pattern would never match a backslash-separated path (filepath.Rel
	// produces "\"-separated relative paths there). normalizeSlashes is used
	// instead of filepath.ToSlash because the latter is a no-op except when
	// GOOS is windows, which would make this branch's behavior untestable
	// outside a Windows build.
	matched, err := filepath.Match(normalizeSlashes(pattern), normalizeSlashes(path))
	if err != nil {
		slog.Debug("ignoring invalid glob pattern", "pattern", pattern, "error", err)
		return false
	}
	return matched
}

// normalizeSlashes converts backslash path separators to forward slashes,
// unconditionally on every build platform (unlike filepath.ToSlash, which
// only does so when GOOS is windows).
func normalizeSlashes(s string) string {
	return strings.ReplaceAll(s, `\`, "/")
}

// matchDirPrefix reports whether path lies within a directory matching dirPattern
// at any depth, implementing gitignore-style "dir/" semantics. Each path segment
// except the last (the filename) is tested against dirPattern with
// filepath.Match, so simple globs like "build*/" also work.
func matchDirPrefix(dirPattern, path string) bool {
	segments := splitPath(path)
	// The trailing segment is the file itself; a directory pattern only matches
	// when there is at least one segment after the matched directory.
	for i := 0; i < len(segments)-1; i++ {
		matched, err := filepath.Match(dirPattern, segments[i])
		if err != nil {
			slog.Debug("ignoring invalid glob pattern", "pattern", dirPattern+"/", "error", err)
			return false
		}
		if matched {
			return true
		}
	}
	return false
}

// matchDoubleStar handles ** glob patterns.
// ** matches zero or more directory segments.
func matchDoubleStar(pattern, path string) bool {
	// Split both on separator
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	return matchSegments(patternParts, pathParts)
}

// matchSegments reports whether pattern (path segments, where "**" matches
// zero or more segments) matches path. It is implemented as an iterative
// dynamic-programming table — the same technique used for classic wildcard
// matching — rather than naive backtracking recursion, which would otherwise
// explore every split-position combination for each "**" token and blow up
// combinatorially on adversarial patterns (e.g. many chained "**" segments
// against a deep, non-matching path). This keeps matching bounded to
// O(len(pattern) * len(path)) filepath.Match calls in the worst case,
// regardless of how many "**" tokens the pattern contains.
//
// A malformed non-"**" segment (invalid filepath.Match syntax) is logged at
// debug level and the whole match is treated as a non-match, mirroring the
// error handling of the sibling matchGlob/matchDirPrefix functions.
func matchSegments(pattern, path []string) bool {
	n := len(pattern)
	m := len(path)

	// dp[i][j] reports whether pattern[:i] matches path[:j].
	dp := make([][]bool, n+1)
	for i := range dp {
		dp[i] = make([]bool, m+1)
	}
	dp[0][0] = true
	for i := 1; i <= n; i++ {
		if pattern[i-1] == "**" {
			dp[i][0] = dp[i-1][0]
		}
	}

	for i := 1; i <= n; i++ {
		segment := pattern[i-1]
		for j := 1; j <= m; j++ {
			if segment == "**" {
				// "**" matches zero segments (dp[i-1][j]) or consumes one more
				// path segment while still matching (dp[i][j-1]).
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
				continue
			}
			matched, err := filepath.Match(segment, path[j-1])
			if err != nil {
				slog.Debug("ignoring invalid glob pattern segment", "segment", segment, "error", err)
				return false
			}
			dp[i][j] = dp[i-1][j-1] && matched
		}
	}

	return dp[n][m]
}

func splitPath(p string) []string {
	// Normalize separators
	p = filepath.ToSlash(p)
	parts := strings.Split(p, "/")
	// Remove empty parts
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

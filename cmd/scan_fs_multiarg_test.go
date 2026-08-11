package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A synthetic AWS access key id that the aws-access-key-id detector matches by
// regex (AKIA + 16 uppercase/digit chars). It is a made-up value, not a live
// credential, and deliberately avoids AWS's canonical "...EXAMPLE" placeholders
// (which the detector filters out as documented false positives).
const syntheticAWSKey = "AKIAZ7XKJQR4TMPLW2NF"

// scanFsJSONFindings runs `scan fs <args...>` end-to-end, writing JSON findings
// to a temp file (which also exercises --output), and returns the decoded
// findings. It isolates the run from the repo's own .leakwatch.yaml by pointing
// cfgFile at an absent path, and disables verification to avoid any network I/O.
func scanFsJSONFindings(t *testing.T, extraArgs ...string) []map[string]any {
	t.Helper()

	isolateConfig(t)

	outFile := filepath.Join(t.TempDir(), "out.json")
	args := append([]string{"scan", "fs"}, extraArgs...)
	args = append(args, "--no-verify", "--format", "json", "--output", outFile)

	err := executeRoot(t, args...)
	// A findings-present run returns FindingsExitError; that is expected here and
	// is not a failure of the test harness.
	if err != nil {
		var fErr *FindingsExitError
		require.True(t, errors.As(err, &fErr), "unexpected scan error: %v", err)
	}

	data, readErr := os.ReadFile(outFile) //nolint:gosec // test-controlled path
	require.NoError(t, readErr)

	var findings []map[string]any
	require.NoError(t, json.Unmarshal(data, &findings))
	return findings
}

// findingFilePaths extracts source.file_path from each decoded finding.
func findingFilePaths(findings []map[string]any) []string {
	paths := make([]string, 0, len(findings))
	for _, f := range findings {
		src, _ := f["source"].(map[string]any)
		if src == nil {
			continue
		}
		if p, ok := src["file_path"].(string); ok {
			paths = append(paths, p)
		}
	}
	return paths
}

// findingDetectorIDs extracts detector_id from each decoded finding.
func findingDetectorIDs(findings []map[string]any) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		if id, ok := f["detector_id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func TestScanFs_SingleFile_ScansOnlyThatFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	sibling := filepath.Join(dir, "sibling.txt")
	require.NoError(t, os.WriteFile(target, []byte("key = "+syntheticAWSKey), 0o600))
	require.NoError(t, os.WriteFile(sibling, []byte("key = "+syntheticAWSKey), 0o600))

	findings := scanFsJSONFindings(t, target)

	paths := findingFilePaths(findings)
	require.Len(t, paths, 1, "only the targeted file should be scanned")
	assert.Equal(t, "target.txt", paths[0])
	assert.NotContains(t, paths, "sibling.txt")
}

func TestScanFs_DirAndFile_ScansBoth(t *testing.T) {
	// A directory root containing one secret, plus a standalone file root with
	// another secret. Both must be scanned in a single invocation.
	dirRoot := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dirRoot, "in_dir.txt"), []byte("key = "+syntheticAWSKey), 0o600))

	fileDir := t.TempDir()
	fileRoot := filepath.Join(fileDir, "standalone.txt")
	require.NoError(t, os.WriteFile(fileRoot, []byte("key = "+syntheticAWSKey), 0o600))

	findings := scanFsJSONFindings(t, dirRoot, fileRoot)

	paths := findingFilePaths(findings)
	require.Len(t, paths, 2)
	assert.ElementsMatch(t, []string{"in_dir.txt", "standalone.txt"}, paths)
}

func TestScanFs_ExcludeDetectors_SuppressesDetector(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "creds.txt"), []byte("key = "+syntheticAWSKey), 0o600))

	// Baseline: without exclusion the aws-access-key-id detector fires.
	baseline := scanFsJSONFindings(t, dir)
	assert.Contains(t, findingDetectorIDs(baseline), "aws-access-key-id",
		"aws-access-key-id should fire without exclusion")

	// With --exclude-detectors the detector is suppressed and no finding remains.
	excluded := scanFsJSONFindings(t, dir, "--exclude-detectors", "aws-access-key-id")
	assert.NotContains(t, findingDetectorIDs(excluded), "aws-access-key-id",
		"aws-access-key-id must be suppressed by --exclude-detectors")
}

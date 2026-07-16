package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/HodeTech/leakwatch/internal/scanner"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// executeRoot runs the real root command with the given args, capturing cobra's
// own output so it does not leak into the test log, and returns the RunE error.
//
// It first resets flag state across the command tree so a flag set by an earlier
// Execute (cobra retains flag values and their Changed state between runs) cannot
// leak into a later one — which otherwise makes these tests order- and
// -count-dependent.
func executeRoot(t *testing.T, args ...string) error {
	t.Helper()
	resetFlagsTree(rootCmd)
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

// resetFlagsTree restores every command's flags to their defaults and clears the
// Changed marker, recursively. The root persistent flags bound to package vars
// (--config -> cfgFile, --log-level -> logLevel) are left untouched so a test's
// isolateConfig setting survives.
func resetFlagsTree(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "config" || f.Name == "log-level" {
			return
		}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	})
	for _, sub := range cmd.Commands() {
		resetFlagsTree(sub)
	}
}

// isolateConfig points the package-level cfgFile at a nonexistent path so a scan
// command under test resolves to built-in defaults regardless of any stray
// .leakwatch.yaml in the working directory.
func isolateConfig(t *testing.T) {
	t.Helper()
	prev := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "none.yaml")
	t.Cleanup(func() { cfgFile = prev })
}

func TestRunInit(t *testing.T) {
	t.Run("creates config when absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".leakwatch.yaml")
		require.NoError(t, executeRoot(t, "init", "--output", path))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(data), "Leakwatch Configuration")
	})

	t.Run("errors when file exists without force", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".leakwatch.yaml")
		require.NoError(t, os.WriteFile(path, []byte("existing"), 0o644))

		err := executeRoot(t, "init", "--output", path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")

		data, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		assert.Equal(t, "existing", string(data), "existing file must be left untouched")
	})

	t.Run("overwrites with force", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".leakwatch.yaml")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))

		require.NoError(t, executeRoot(t, "init", "--output", path, "--force"))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(data), "Leakwatch Configuration")
	})
}

func TestRunScanImage_InvalidReference_ReturnsError(t *testing.T) {
	isolateConfig(t)
	// A malformed image reference fails at Validate (name.ParseReference) before
	// any network pull, so this exercises runScanImage deterministically offline.
	err := executeRoot(t, "scan", "image", "Invalid Image Ref!!")
	require.Error(t, err)

	var fErr *FindingsExitError
	assert.False(t, errors.As(err, &fErr), "a validation failure must not be a findings exit")
}

func TestRunScanS3_InvalidConcurrency_ReturnsError(t *testing.T) {
	isolateConfig(t)
	// --concurrency 0 fails config validation inside runScanS3's loadScanConfig,
	// before any AWS client/network call.
	err := executeRoot(t, "scan", "s3", "my-bucket", "--concurrency", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrency")
}

func TestRunScanS3_RegistersSourceFlags(t *testing.T) {
	for _, name := range []string{"prefix", "region", "exclude"} {
		assert.NotNil(t, scanS3Cmd.Flags().Lookup(name), "scan s3 must register --%s", name)
	}
}

func TestRunScanGCS_InvalidConcurrency_ReturnsError(t *testing.T) {
	isolateConfig(t)
	err := executeRoot(t, "scan", "gcs", "my-bucket", "--concurrency", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrency")
}

func TestRunScanGCS_RegistersSourceFlags(t *testing.T) {
	for _, name := range []string{"prefix", "project", "exclude"} {
		assert.NotNil(t, scanGCSCmd.Flags().Lookup(name), "scan gcs must register --%s", name)
	}
}

func TestRunScanSlack_MissingToken_ReturnsError(t *testing.T) {
	isolateConfig(t)
	t.Setenv("LEAKWATCH_SLACK_TOKEN", "")

	err := executeRoot(t, "scan", "slack")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}

func TestRunScanSlack_TokenFromEnv_ReachesDateValidation(t *testing.T) {
	isolateConfig(t)
	// With a token resolved from the environment, an invalid --since date is
	// rejected before any Slack API call — proving token fallback works.
	t.Setenv("LEAKWATCH_SLACK_TOKEN", "xoxb-fake-test-token")

	err := executeRoot(t, "scan", "slack", "--since", "not-a-date")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --since date")
}

func TestRunScanRepos_AllReposFail_ReturnsAggregateError(t *testing.T) {
	isolateConfig(t)
	// Two local paths that are not git repositories fail to open locally (no
	// network), so both repo scans fail and the aggregate error surfaces.
	d1 := filepath.Join(t.TempDir(), "not-a-repo-1")
	d2 := filepath.Join(t.TempDir(), "not-a-repo-2")

	err := executeRoot(t, "scan", "repos", d1, d2, "--no-verify")
	require.Error(t, err)

	var fErr *FindingsExitError
	assert.False(t, errors.As(err, &fErr), "failed repo scans must not be reported as findings")
	assert.Contains(t, err.Error(), "repository scans failed")
}

// TestFinishScan_ExitCodeContract verifies the exit-code decision: findings win
// over interruption, an interrupted scan with no findings is never a clean exit,
// and a clean completed scan returns nil.
func TestFinishScan_ExitCodeContract(t *testing.T) {
	base := &scanner.Config{Format: "json"}

	t.Run("findings return FindingsExitError", func(t *testing.T) {
		result := &engine.ScanResult{Findings: []finding.Finding{{ID: "x", Severity: finding.SeverityHigh}}}
		err := finishScan(base, result, "fs", nil)
		var fErr *FindingsExitError
		require.ErrorAs(t, err, &fErr)
		assert.Equal(t, 1, fErr.Count)
	})

	t.Run("interrupted with no findings returns InterruptedExitError", func(t *testing.T) {
		result := &engine.ScanResult{Findings: []finding.Finding{}, Interrupted: true}
		err := finishScan(base, result, "fs", context.Canceled)
		var iErr *InterruptedExitError
		require.ErrorAs(t, err, &iErr)
	})

	t.Run("findings take precedence over interruption", func(t *testing.T) {
		result := &engine.ScanResult{Findings: []finding.Finding{{ID: "x"}}, Interrupted: true}
		err := finishScan(base, result, "fs", context.Canceled)
		var fErr *FindingsExitError
		require.ErrorAs(t, err, &fErr)
	})

	t.Run("clean completed scan returns nil", func(t *testing.T) {
		result := &engine.ScanResult{Findings: []finding.Finding{}}
		require.NoError(t, finishScan(base, result, "fs", nil))
	})
}

func TestLoadScanConfig_InvalidMinSeverity_ReturnsError(t *testing.T) {
	isolateConfig(t)
	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--min-severity", "crital"}))

	_, err := loadScanConfig(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --min-severity")
}

func TestLoadScanConfig_ValidMinSeverity_Parsed(t *testing.T) {
	isolateConfig(t)
	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--min-severity", "high"}))

	cfg, err := loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, finding.SeverityHigh, cfg.MinSeverity)
}

func TestLoadScanConfig_MalformedConfig_IsFatal(t *testing.T) {
	clearScanEnv(t)
	writeConfigFile(t, "scan:\n  concurrency: [unterminated\n")

	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags(nil))

	_, err := loadScanConfig(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse config file")
}

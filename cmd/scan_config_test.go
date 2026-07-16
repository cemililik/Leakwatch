package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestScanCmd builds a cobra command carrying the same common scan flags that
// the real scan commands register, so loadScanConfig can resolve configuration
// against an isolated Viper exactly as it does in production.
func newTestScanCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return nil }}
	flags := cmd.Flags()
	addCommonScanFlags(flags)
	addExcludePathFlag(flags)
	addVerifyFlags(flags)
	return cmd
}

// writeConfigFile writes a temporary .leakwatch.yaml and points the package-level
// cfgFile var at it for the duration of the test.
func writeConfigFile(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".leakwatch.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	prev := cfgFile
	cfgFile = path
	t.Cleanup(func() { cfgFile = prev })
}

// clearScanEnv ensures no LEAKWATCH_ env vars leak in from the surrounding shell
// or a previous case. The original value is captured and restored on cleanup so
// tests stay hermetic without relying on t.Setenv (which sets, not unsets).
func clearScanEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LEAKWATCH_SCAN_CONCURRENCY",
		"LEAKWATCH_SCAN_MAX_FILE_SIZE",
		"LEAKWATCH_OUTPUT_FORMAT",
		"LEAKWATCH_OUTPUT_SHOW_RAW",
	} {
		prev, had := os.LookupEnv(k)
		require.NoError(t, os.Unsetenv(k))
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(k, prev)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

func TestLoadScanConfig_Concurrency_FlagBeatsEnvBeatsConfigBeatsDefault(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		env      map[string]string
		flagSet  bool
		flagVal  string
		expected int
	}{
		{
			name:     "default",
			expected: runtime.NumCPU(),
		},
		{
			name:     "config overrides default",
			config:   "scan:\n  concurrency: 2\n",
			expected: 2,
		},
		{
			name:     "env overrides config",
			config:   "scan:\n  concurrency: 2\n",
			env:      map[string]string{"LEAKWATCH_SCAN_CONCURRENCY": "5"},
			expected: 5,
		},
		{
			name:     "flag overrides env and config",
			config:   "scan:\n  concurrency: 2\n",
			env:      map[string]string{"LEAKWATCH_SCAN_CONCURRENCY": "5"},
			flagSet:  true,
			flagVal:  "8",
			expected: 8,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearScanEnv(t)
			if tc.config != "" {
				writeConfigFile(t, tc.config)
			} else {
				prev := cfgFile
				cfgFile = filepath.Join(t.TempDir(), "absent.yaml")
				t.Cleanup(func() { cfgFile = prev })
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			cmd := newTestScanCmd()
			args := []string{}
			if tc.flagSet {
				args = append(args, "--concurrency", tc.flagVal)
			}
			require.NoError(t, cmd.ParseFlags(args))

			cfg, err := loadScanConfig(cmd)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.Concurrency)
		})
	}
}

func TestLoadScanConfig_MaxFileSize_PrecedenceHolds(t *testing.T) {
	clearScanEnv(t)
	writeConfigFile(t, "scan:\n  max-file-size: 1024\n")

	// config tier
	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	cfg, err := loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, int64(1024), cfg.MaxFileSize)

	// env beats config
	t.Setenv("LEAKWATCH_SCAN_MAX_FILE_SIZE", "2048")
	cmd = newTestScanCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	cfg, err = loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, int64(2048), cfg.MaxFileSize)

	// flag beats env
	cmd = newTestScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--max-file-size", "4096"}))
	cfg, err = loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, int64(4096), cfg.MaxFileSize)
}

func TestLoadScanConfig_Format_EnvAndConfigHonoredWhenFlagUnset(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		env      map[string]string
		flagSet  bool
		flagVal  string
		expected string
	}{
		{name: "default json", expected: "json"},
		{name: "config table honored", config: "output:\n  format: table\n", expected: "table"},
		{
			name:     "env table overrides config csv",
			config:   "output:\n  format: csv\n",
			env:      map[string]string{"LEAKWATCH_OUTPUT_FORMAT": "table"},
			expected: "table",
		},
		{
			name:     "flag sarif overrides env table",
			env:      map[string]string{"LEAKWATCH_OUTPUT_FORMAT": "table"},
			flagSet:  true,
			flagVal:  "sarif",
			expected: "sarif",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearScanEnv(t)
			if tc.config != "" {
				writeConfigFile(t, tc.config)
			} else {
				prev := cfgFile
				cfgFile = filepath.Join(t.TempDir(), "absent.yaml")
				t.Cleanup(func() { cfgFile = prev })
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			cmd := newTestScanCmd()
			args := []string{}
			if tc.flagSet {
				args = append(args, "--format", tc.flagVal)
			}
			require.NoError(t, cmd.ParseFlags(args))

			cfg, err := loadScanConfig(cmd)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cfg.Format)
		})
	}
}

func TestLoadScanConfig_ShowRaw_FlagFalseOverridesConfigTrue(t *testing.T) {
	clearScanEnv(t)
	writeConfigFile(t, "output:\n  show-raw: true\n")

	// Without the flag, config show-raw: true takes effect.
	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	cfg, err := loadScanConfig(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.ShowRaw, "config show-raw: true should apply when flag unset")

	// Explicit --show-raw=false must override config show-raw: true (OUT-m-04).
	cmd = newTestScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--show-raw=false"}))
	cfg, err = loadScanConfig(cmd)
	require.NoError(t, err)
	assert.False(t, cfg.ShowRaw, "--show-raw=false must override config show-raw: true")
}

func TestLoadScanConfig_IsolatedPerCommand_NoCrossLeak(t *testing.T) {
	clearScanEnv(t)
	prev := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "absent.yaml")
	t.Cleanup(func() { cfgFile = prev })

	// Command A sets concurrency 4; command B leaves it at default. Resolving B
	// after A must not inherit A's value (the SYS-07a/b regression).
	cmdA := newTestScanCmd()
	require.NoError(t, cmdA.ParseFlags([]string{"--concurrency", "4"}))
	cfgA, err := loadScanConfig(cmdA)
	require.NoError(t, err)
	assert.Equal(t, 4, cfgA.Concurrency)

	cmdB := newTestScanCmd()
	require.NoError(t, cmdB.ParseFlags(nil))
	cfgB, err := loadScanConfig(cmdB)
	require.NoError(t, err)
	assert.Equal(t, runtime.NumCPU(), cfgB.Concurrency)
}

func TestShouldEnableColor_DecisionTable(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		outputFile  string
		stdoutIsTTY bool
		noColor     bool
		want        bool
	}{
		{"table tty no NO_COLOR", "table", "", true, false, true},
		{"table but not a tty", "table", "", false, false, false},
		{"table tty but NO_COLOR set", "table", "", true, true, false},
		{"table written to file", "table", "out.txt", true, false, false},
		{"json never colored", "json", "", true, false, false},
		{"sarif never colored", "sarif", "", true, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, shouldEnableColor(tc.format, tc.outputFile, tc.stdoutIsTTY, tc.noColor))
		})
	}
}

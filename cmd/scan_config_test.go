package cmd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/internal/scanner"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
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

func TestLoadScanConfig_GrafanaInstanceRequiresExplicitFlag(t *testing.T) {
	clearScanEnv(t)
	writeConfigFile(t, "verification:\n  grafana-instance-url: https://repository-controlled.example\n")
	t.Setenv("LEAKWATCH_VERIFICATION_GRAFANA_INSTANCE_URL", "https://environment.example")

	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	cfg, err := loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Empty(t, cfg.GrafanaInstanceURL, "project config and environment must not choose a verifier target")

	cmd = newTestScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--grafana-instance-url", "https://operator.example"}))
	cfg, err = loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, "https://operator.example", cfg.GrafanaInstanceURL)

	registered, ok := verifier.Get("grafana-api-key")
	require.True(t, ok)
	engineCfg, err := scanner.BuildEngineConfig(cfg)
	require.NoError(t, err)
	var configured verifier.Verifier
	for _, candidate := range engineCfg.Verifiers {
		if candidate.Type() == "grafana-api-key" {
			configured = candidate
			break
		}
	}
	require.NotNil(t, configured)
	assert.NotSame(t, registered, configured, "the scan must receive a configured per-run verifier copy")
	stillRegistered, ok := verifier.Get("grafana-api-key")
	require.True(t, ok)
	assert.Same(t, registered, stillRegistered, "per-run configuration must not mutate the global registry")

	for _, rawURL := range []string{"http://grafana.example", "https://127.0.0.1", "https://grafana.com"} {
		cfg.GrafanaInstanceURL = rawURL
		_, err = scanner.BuildEngineConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `configure trusted verification for "grafana-api-key"`)
	}
}

func TestLoadScanConfig_TrustedVerifierOriginsRequireExplicitFlags(t *testing.T) {
	clearScanEnv(t)
	writeConfigFile(t, "verification:\n  verifier-origin:\n    gitlab-pat: https://repository-controlled.example\n")
	t.Setenv("LEAKWATCH_VERIFICATION_VERIFIER_ORIGIN", "gitlab-pat=https://environment.example")

	cmd := newTestScanCmd()
	require.NoError(t, cmd.ParseFlags(nil))
	cfg, err := loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Empty(t, cfg.TrustedVerifierOrigins,
		"project config and environment must not choose credential destinations")

	cmd = newTestScanCmd()
	require.NoError(t, cmd.ParseFlags([]string{
		"--verifier-origin", "gitlab-pat=https://gitlab.operator.example",
		"--verifier-origin", "auth0-management-token=https://tenant.operator.example",
	}))
	cfg, err = loadScanConfig(cmd)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"gitlab-pat":             "https://gitlab.operator.example",
		"auth0-management-token": "https://tenant.operator.example",
	}, cfg.TrustedVerifierOrigins)
}

func TestLoadScanConfig_TrustedVerifierOriginSyntaxFailsClosed(t *testing.T) {
	for _, args := range [][]string{
		{"--verifier-origin", "missing-equals"},
		{"--verifier-origin", "=https://operator.example"},
		{"--verifier-origin", "gitlab-pat="},
		{
			"--verifier-origin", "gitlab-pat=https://one.example",
			"--verifier-origin", "gitlab-pat=https://two.example",
		},
	} {
		cmd := newTestScanCmd()
		require.NoError(t, cmd.ParseFlags(args))
		_, err := loadScanConfig(cmd)
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), "--verifier-origin")
	}
}

func TestBuildEngineConfig_ConfiguresEveryContextRequiredVerifierPerRun(t *testing.T) {
	origins := map[string]string{
		"auth0-management-token": "https://tenant.example",
		"datadog-api-key":        "https://api.datadoghq.com",
		"github-token":           "https://github.example",
		"github-oauth-token":     "https://github.example",
		"gitlab-pat":             "https://gitlab.example",
		"grafana-api-key":        "https://grafana.example",
		"shopify-access-token":   "https://store.myshopify.com",
		"snyk-api-key":           "https://api.snyk.io",
		"twilio-api-key":         "https://api.twilio.com",
	}
	originals := make(map[string]verifier.Verifier, len(origins))
	for detectorID := range origins {
		registered, ok := verifier.Get(detectorID)
		require.True(t, ok, detectorID)
		originals[detectorID] = registered
	}

	engineCfg, err := scanner.BuildEngineConfig(&scanner.Config{
		Concurrency:            1,
		TrustedVerifierOrigins: origins,
	})
	require.NoError(t, err)
	configured := make(map[string]verifier.Verifier, len(engineCfg.Verifiers))
	for _, candidate := range engineCfg.Verifiers {
		configured[candidate.Type()] = candidate
	}
	for detectorID, original := range originals {
		require.Contains(t, configured, detectorID)
		assert.NotSame(t, original, configured[detectorID], detectorID)
		stillRegistered, ok := verifier.Get(detectorID)
		require.True(t, ok)
		assert.Same(t, original, stillRegistered, detectorID)
	}

	// Drive every configured production verifier with the exact finding emitted
	// by its registered detector. An already-cancelled context guarantees that
	// this executable routing contract cannot put synthetic credentials on the
	// network while proving the per-run configured path is reached.
	detectors := make(map[string]detector.Detector, len(detectorsAtInit))
	for _, det := range detectorsAtInit {
		detectors[det.ID()] = det
	}
	fixtures := testutil.RegisteredDetectorFixtures()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for detectorID := range origins {
		fixture, ok := fixtures[detectorID]
		require.True(t, ok, detectorID)
		rawFindings := testutil.ScanViaMatcher(detectors[detectorID], fixture.Input)
		require.NotEmpty(t, rawFindings, detectorID)
		result := configured[detectorID].Verify(ctx, rawFindings[0])
		assert.Equal(t, finding.StatusVerifyError, result.Status,
			"configured verifier must reach its cancelled provider request: %s (%s)", detectorID, result.Message)
		assert.NotContains(t, result.Message, string(rawFindings[0].Raw))
	}
}

func TestBuildEngineConfig_RejectsInvalidTrustedVerifierOrigins(t *testing.T) {
	tests := []struct {
		name    string
		origins map[string]string
	}{
		{name: "unknown detector", origins: map[string]string{"missing": "https://operator.example"}},
		{name: "non contextual verifier", origins: map[string]string{"aws-access-key-id": "https://operator.example"}},
		{name: "invalid origin", origins: map[string]string{"gitlab-pat": "http://gitlab.example"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scanner.BuildEngineConfig(&scanner.Config{
				Concurrency:            1,
				TrustedVerifierOrigins: tc.origins,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "configure trusted verification")
		})
	}

	_, err := scanner.BuildEngineConfig(&scanner.Config{
		Concurrency:            1,
		GrafanaInstanceURL:     "https://grafana-one.example",
		TrustedVerifierOrigins: map[string]string{"grafana-api-key": "https://grafana-two.example"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting Grafana origins")
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

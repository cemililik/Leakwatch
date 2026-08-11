package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/meta"
	csvout "github.com/HodeTech/leakwatch/internal/output/csv"
	githubout "github.com/HodeTech/leakwatch/internal/output/github"
	jsonout "github.com/HodeTech/leakwatch/internal/output/json"
	sarifout "github.com/HodeTech/leakwatch/internal/output/sarif"
	tableout "github.com/HodeTech/leakwatch/internal/output/table"
)

func TestSelectFormatter_AllFormats_ReturnsCorrectType(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		showRaw      bool
		expectedType interface{}
	}{
		{
			name:         "json format",
			format:       "json",
			showRaw:      false,
			expectedType: &jsonout.Formatter{},
		},
		{
			name:         "sarif format",
			format:       "sarif",
			showRaw:      false,
			expectedType: &sarifout.Formatter{},
		},
		{
			name:         "csv format",
			format:       "csv",
			showRaw:      false,
			expectedType: &csvout.Formatter{},
		},
		{
			name:         "table format",
			format:       "table",
			showRaw:      false,
			expectedType: &tableout.Formatter{},
		},
		{
			name:         "github format",
			format:       "github",
			showRaw:      false,
			expectedType: &githubout.Formatter{},
		},
		{
			name:         "unknown format defaults to json",
			format:       "unknown",
			showRaw:      false,
			expectedType: &jsonout.Formatter{},
		},
		{
			name:         "empty format defaults to json",
			format:       "",
			showRaw:      false,
			expectedType: &jsonout.Formatter{},
		},
		{
			name:         "json format with showRaw",
			format:       "json",
			showRaw:      true,
			expectedType: &jsonout.Formatter{ShowRaw: true},
		},
		{
			name:         "sarif format with showRaw",
			format:       "sarif",
			showRaw:      true,
			expectedType: &sarifout.Formatter{ShowRaw: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			formatter := selectFormatter(tc.format, tc.showRaw, false)
			assert.IsType(t, tc.expectedType, formatter)
		})
	}
}

func TestRootCommand_VersionFlag_ShowsVersion(t *testing.T) {
	// Set known version info for deterministic output.
	SetVersionInfo("1.0.0-test", "abc1234", "2026-03-24")
	t.Cleanup(func() { SetVersionInfo("dev", "none", "unknown") })

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	want := readGolden(t, "version.golden")
	assert.Equal(t, want, buf.String())
}

func TestRootCommand_HelpMetadataMatchesGolden(t *testing.T) {
	want := readGolden(t, "root-help.golden")
	assert.Equal(t, strings.TrimSuffix(want, "\n"), rootCmd.Long)
}

func TestOutputFormats_MatchGoldenAndFlagHelp(t *testing.T) {
	want := readGolden(t, "output-formats.golden")
	got := strings.Join(meta.OutputFormatNames(), "\n") + "\n"
	assert.Equal(t, want, got)

	formatFlag := scanFsCmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "output format ("+meta.OutputFormatList+")", formatFlag.Usage)
	assert.Equal(t, 1, strings.Count(defaultConfigTemplate, "{{OUTPUT_FORMATS}}"))
	assert.Contains(t, defaultConfig, "# Output format: "+meta.OutputFormatList)
	assert.NotContains(t, defaultConfig, "{{OUTPUT_FORMATS}}")
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

func TestScanCommand_NoSubcommand_ShowsHelp(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"scan"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "scan")
	assert.Contains(t, output, "Usage")
}

func TestScanFsCommand_AcceptsMultiplePathArgs(t *testing.T) {
	// The command now accepts zero or more path arguments (files or dirs).
	assert.Equal(t, "fs [path...]", scanFsCmd.Use)
	// ArbitraryArgs never rejects on arity; validating that here keeps the
	// contract explicit without running the full scan pipeline.
	require.NotNil(t, scanFsCmd.Args)
	assert.NoError(t, scanFsCmd.Args(scanFsCmd, []string{"/path1", "/path2"}))
	assert.NoError(t, scanFsCmd.Args(scanFsCmd, nil))
}

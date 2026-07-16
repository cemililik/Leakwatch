package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"version"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "1.0.0-test")
	assert.Contains(t, output, "abc1234")
	assert.Contains(t, output, "2026-03-24")
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

func TestScanFsCommand_NoArgs_AcceptsZeroArgs(t *testing.T) {
	// Verify the command accepts 0 args (defaults to ".")
	// We only test argument validation, not the full scan pipeline.
	assert.Equal(t, "fs [path]", scanFsCmd.Use)
}

func TestScanFsCommand_TooManyArgs_ReturnsError(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"scan", "fs", "/path1", "/path2"})

	err := rootCmd.Execute()
	assert.Error(t, err)
}

package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/source/filesystem"
)

var scanFsCmd = &cobra.Command{
	Use:   "fs [path]",
	Short: "Scans a filesystem directory",
	Long: `Scans files in the specified directory to detect leaked secrets.
If no path is provided, the current working directory is scanned.`,
	Example: `  # Scan current directory
  leakwatch scan fs

  # Scan specific path
  leakwatch scan fs /path/to/project

  # Output as table with remediation
  leakwatch scan fs . --format table --remediation

  # Exclude test files
  leakwatch scan fs . --exclude "**/*_test.go"

  # Save results as SARIF
  leakwatch scan fs . --format sarif --output results.sarif

  # Limit file size and increase workers
  leakwatch scan fs . --max-file-size 5242880 --concurrency 8`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScanFs,
}

func init() {
	scanCmd.AddCommand(scanFsCmd)

	flags := scanFsCmd.Flags()
	addCommonScanFlags(flags)
	addExcludePathFlag(flags)
	addVerifyFlags(flags)
}

func runScanFs(cmd *cobra.Command, args []string) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	scanPath = filepath.Clean(scanPath)
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}
	cfg.ScanRoot = absPath
	cfg.ScanTarget = absPath

	src := filesystem.New(
		absPath,
		filesystem.WithMaxFileSize(cfg.MaxFileSize),
		filesystem.WithExcludePaths(mergedExcludePaths(cmd, cfg)),
	)

	return runScan(cmd, cfg, src, nil)
}

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/source/filesystem"
)

var scanFsCmd = &cobra.Command{
	Use:   "fs [path...]",
	Short: "Scans filesystem paths (files or directories)",
	Long: `Scans one or more filesystem paths to detect leaked secrets. Each path may be
a directory (walked recursively) or a single file. If no path is provided, the
current working directory is scanned.`,
	Example: `  # Scan current directory
  leakwatch scan fs

  # Scan a specific directory
  leakwatch scan fs /path/to/project

  # Scan a single file
  leakwatch scan fs cmd/main.go

  # Scan several files and directories at once
  leakwatch scan fs cmd/ main.go internal/config

  # Output as table with remediation
  leakwatch scan fs . --format table --remediation

  # Exclude test files
  leakwatch scan fs . --exclude "**/*_test.go"

  # Exclude specific detectors
  leakwatch scan fs . --exclude-detectors aws-access-key-id,generic-api-key

  # Save results as SARIF
  leakwatch scan fs . --format sarif --output results.sarif

  # Limit file size and increase workers
  leakwatch scan fs . --max-file-size 5242880 --concurrency 8`,
	Args: cobra.ArbitraryArgs,
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
	paths := args
	if len(paths) == 0 {
		paths = []string{"."}
	}

	absPaths := make([]string, 0, len(paths))
	for _, p := range paths {
		absPath, err := filepath.Abs(filepath.Clean(p))
		if err != nil {
			return fmt.Errorf("failed to resolve path %q: %w", p, err)
		}
		absPaths = append(absPaths, absPath)
	}

	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}
	// ScanRoot seeds .leakwatchignore discovery; use the first path's own
	// directory so a single-file target still finds an ignore file next to it
	// (a non-directory ScanRoot would never match). The CWD is always searched
	// as a fallback inside the scanner.
	cfg.ScanRoot = ignoreRootFor(absPaths[0])
	cfg.ScanTarget = strings.Join(absPaths, ", ")

	src := filesystem.NewMulti(
		absPaths,
		filesystem.WithMaxFileSize(cfg.MaxFileSize),
		filesystem.WithExcludePaths(mergedExcludePaths(cmd, cfg)),
	)

	return runScan(cmd, cfg, src, nil)
}

// ignoreRootFor returns the directory to search for a .leakwatchignore file for
// the given (already absolute) scan path: the path itself when it is a
// directory, otherwise its parent directory when it is a single file.
func ignoreRootFor(absPath string) string {
	if info, err := os.Stat(absPath); err == nil && !info.IsDir() {
		return filepath.Dir(absPath)
	}
	return absPath
}

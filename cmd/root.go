// Package cmd defines Leakwatch CLI commands.
// This package is a thin wiring layer; it must not contain business logic.
package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/meta"
)

var (
	cfgFile  string
	logLevel string

	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetVersionInfo sets build information (called from main.go).
func SetVersionInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
}

// FindingsExitError indicates that secrets were found (exit code 1).
type FindingsExitError struct {
	Count int
}

func (e *FindingsExitError) Error() string {
	return fmt.Sprintf("%d secret(s) found", e.Count)
}

// InterruptedExitError indicates the scan was interrupted (SIGINT/SIGTERM) before
// completing, so its partial results must not be trusted as a clean pass. It maps
// to exit code 3, distinct from findings (1) and generic errors (2), so a CI
// pipeline can never observe a clean exit 0 for a scan that did not finish.
type InterruptedExitError struct{}

func (e *InterruptedExitError) Error() string {
	return "scan interrupted before completion"
}

var rootCmd = &cobra.Command{
	Use:   "leakwatch",
	Short: "Detects leaked secrets in codebases",
	Long:  rootLongDescription(),
	Example: `  # Quick scan of current directory
  leakwatch scan fs .

  # Scan a Git repository with verification
  leakwatch scan git https://github.com/org/repo.git

  # Scan and output SARIF for GitHub Code Scanning
  leakwatch scan fs . --format sarif --output results.sarif

  # Scan with remediation guidance
  leakwatch scan fs . --remediation --format table

  # Show only verified active secrets
  leakwatch scan git . --only-verified`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func rootLongDescription() string {
	capabilities := meta.VerificationCapabilityCounts()
	return fmt.Sprintf(`Leakwatch is a high-performance security tool that detects, verifies, and reports
leaked secrets (API keys, passwords, certificates) in codebases, Git histories,
container images, cloud storage buckets, and Slack workspaces.

Features:
  - %d built-in secret detectors covering AWS, GitHub, Slack, Stripe, JWT, and more
  - %d verification implementations: %d direct-live, %d context-required, %d format-only
  - Scans filesystems, Git repos, container images, S3, GCS, and Slack
  - Multiple output formats: %s
  - Aho-Corasick pre-filtering for fast multi-pattern matching
  - Concurrent worker pool architecture for high throughput
  - Custom rules via YAML configuration
  - .leakwatchignore and inline ignore support`,
		meta.Detectors,
		meta.Verifiers,
		capabilities.Live,
		capabilities.RequiresContext,
		capabilities.FormatOnly,
		meta.OutputFormatList,
	)
}

// Execute runs the root command and returns the process exit code:
//
//	0  clean, completed scan with no findings
//	1  findings were reported (FindingsExitError)
//	2  a generic error (bad flags, config parse failure, scan failure)
//	3  the scan was interrupted before completing (InterruptedExitError)
func Execute() int {
	// ExecuteC returns the command that actually ran/failed so the error hint can
	// point at that subcommand's own --help rather than the top-level one.
	cmd, err := rootCmd.ExecuteC()
	code := exitCodeForError(err)
	if code == 0 || code == 1 {
		return code
	}

	if code == 3 {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		slog.Debug("scan interrupted", "error", err)
		return 3
	}

	// Print user-friendly error pointing at the failing command's own help.
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	fmt.Fprintf(os.Stderr, "\nRun '%s --help' for usage information.\n", cmd.CommandPath())
	slog.Debug("command failed", "error", err)
	return 2
}

// exitCodeForError is the single testable mapping between typed command errors
// and the process contract documented above.
func exitCodeForError(err error) int {
	if err == nil {
		return 0
	}
	var findingsErr *FindingsExitError
	if errors.As(err, &findingsErr) {
		return 1
	}
	var interruptedErr *InterruptedExitError
	if errors.As(err, &interruptedErr) {
		return 3
	}
	return 2
}

func init() {
	// Config discovery is performed per-command in an isolated Viper instance
	// (see newScanViper in scan_common.go); the global Viper is intentionally not
	// populated here. Binding every scan command's flags to the same global keys
	// caused the last init() to win, so one command's flag defaults masked the
	// active command's flags (SYS-07a/b). Only the logger is initialized globally.
	cobra.OnInitialize(initLogger)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .leakwatch.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "log level (debug, info, warn, error)")
}

func initLogger() {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		slog.Warn("unknown log level, falling back to warn", "level", logLevel)
		level = slog.LevelWarn
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

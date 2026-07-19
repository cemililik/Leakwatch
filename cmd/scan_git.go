package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	gitsource "github.com/HodeTech/leakwatch/internal/source/git"
)

var scanGitCmd = &cobra.Command{
	Use:   "git <url_or_path>",
	Short: "Scans a Git repository",
	Long: `Scans the entire commit history of the specified Git repository to detect
leaked secrets. Both local and remote (HTTP/SSH) repositories are supported.

The scanner examines every commit diff for secrets that may have been introduced
and later removed. Use --since or --since-commit to limit the scan range,
and --branch to target a specific branch.`,
	Example: `  # Scan a local Git repository
  leakwatch scan git .

  # Scan a remote repository
  leakwatch scan git https://github.com/org/repo.git

  # Scan only commits from the last 30 days
  leakwatch scan git . --since 2026-02-23

  # Scan a specific branch
  leakwatch scan git . --branch develop

  # Scan changes since a specific commit
  leakwatch scan git . --since-commit abc1234

  # Shallow clone scan (faster for large repos)
  leakwatch scan git https://github.com/org/repo.git --depth 50

  # Show only verified secrets in table format
  leakwatch scan git . --only-verified --format table`,
	Args: cobra.ExactArgs(1),
	RunE: runScanGit,
}

func init() {
	scanCmd.AddCommand(scanGitCmd)

	flags := scanGitCmd.Flags()
	addCommonScanFlags(flags)
	addExcludePathFlag(flags)
	flags.String("since", "", "scan commits after this date (YYYY-MM-DD)")
	flags.String("since-commit", "", "scan changes from this commit to HEAD")
	flags.String("branch", "", "branch to scan")
	flags.Int("depth", 0, "clone depth (remote repos only, 0=all)")

	addVerifyFlags(flags)
}

func runScanGit(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	opts := []gitsource.Option{gitsource.WithMaxFileSize(cfg.MaxFileSize)}

	if excludes := mergedExcludePaths(cmd, cfg); len(excludes) > 0 {
		opts = append(opts, gitsource.WithExcludePaths(excludes))
	}

	if since := flagString(cmd, "since"); since != "" {
		t, err := time.Parse("2006-01-02", since)
		if err != nil {
			return fmt.Errorf("invalid date format (expected YYYY-MM-DD): %w", err)
		}
		opts = append(opts, gitsource.WithSince(t))
	}

	if sinceCommit := flagString(cmd, "since-commit"); sinceCommit != "" {
		opts = append(opts, gitsource.WithSinceCommit(sinceCommit))
	}

	if branch := flagString(cmd, "branch"); branch != "" {
		opts = append(opts, gitsource.WithBranch(branch))
	}

	if depth := flagInt(cmd, "depth"); depth > 0 {
		opts = append(opts, gitsource.WithDepth(depth))
	}

	cfg.ScanTarget = gitsource.SafeDisplayURL(args[0])
	src := gitsource.New(args[0], opts...)

	return runScan(cmd, cfg, src, src)
}

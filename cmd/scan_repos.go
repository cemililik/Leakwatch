package cmd

import (
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/scanner"
	gitsource "github.com/HodeTech/leakwatch/internal/source/git"
)

var scanReposCmd = &cobra.Command{
	Use:   "repos <url1> <url2> [url...]",
	Short: "Scans multiple Git repositories in parallel",
	Long: `Scans multiple Git repositories concurrently. Each repository is cloned
and scanned independently. Results are combined into a single output.`,
	Example: `  # Scan two repositories
  leakwatch scan repos https://github.com/org/repo1.git https://github.com/org/repo2.git

  # Scan multiple repos with higher parallelism
  leakwatch scan repos --parallel 5 \
    https://github.com/org/api.git \
    https://github.com/org/web.git \
    https://github.com/org/infra.git

  # Output combined results as table
  leakwatch scan repos --format table \
    https://github.com/org/repo1.git \
    https://github.com/org/repo2.git`,
	Args: cobra.MinimumNArgs(2),
	RunE: runScanRepos,
}

func init() {
	scanCmd.AddCommand(scanReposCmd)

	flags := scanReposCmd.Flags()
	addCommonScanFlags(flags)
	addExcludePathFlag(flags)
	flags.Int("parallel", 3, "number of repositories to scan in parallel")
	addVerifyFlags(flags)
}

func runScanRepos(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	parallel := flagInt(cmd, "parallel")
	if parallel < 1 {
		parallel = 3
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Reuse the same source options (max file size, exclude-paths) for every repo.
	srcOpts := []gitsource.Option{gitsource.WithMaxFileSize(cfg.MaxFileSize)}
	if excludes := mergedExcludePaths(cmd, cfg); len(excludes) > 0 {
		srcOpts = append(srcOpts, gitsource.WithExcludePaths(excludes))
	}

	cfg.ScanTarget = fmt.Sprintf("%d repositories", len(args))

	// scanner.ScanRepos builds one shared engine (and one shared verifier rate
	// limiter) and reuses it across every repo goroutine, so verification.rate-limit
	// is enforced globally rather than multiplied by --parallel.
	combined, scanErr := scanner.ScanRepos(ctx, cfg, args, srcOpts, parallel)
	if combined == nil {
		// Only an engine-config failure yields a nil combined result.
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	return finishScan(cfg, combined, "repos", scanErr)
}

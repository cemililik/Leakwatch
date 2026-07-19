package cmd

import (
	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/source/container"
)

var scanImageCmd = &cobra.Command{
	Use:   "image <image:tag>",
	Short: "Scans a container image",
	Long: `Scans a container image layer by layer to detect leaked secrets.
Supports Docker Hub, GHCR, ECR, GCR and other OCI-compatible registries.
Does not require a running Docker daemon.`,
	Example: `  # Scan a Docker Hub image
  leakwatch scan image nginx:latest

  # Scan a private registry image
  leakwatch scan image ghcr.io/org/myapp:v1.2.0

  # Scan an AWS ECR image
  leakwatch scan image 123456789.dkr.ecr.us-east-1.amazonaws.com/myapp:latest

  # Output results as JSON to a file
  leakwatch scan image myapp:latest --format json --output results.json

  # Show only verified active secrets
  leakwatch scan image myapp:latest --only-verified`,
	Args: cobra.ExactArgs(1),
	RunE: runScanImage,
}

func init() {
	scanCmd.AddCommand(scanImageCmd)

	flags := scanImageCmd.Flags()
	addCommonScanFlags(flags)
	addExcludePathFlag(flags)
	addVerifyFlags(flags)
}

func runScanImage(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	cfg.ScanTarget = args[0]

	opts := []container.Option{container.WithMaxFileSize(cfg.MaxFileSize)}
	if excludes := mergedExcludePaths(cmd, cfg); len(excludes) > 0 {
		opts = append(opts, container.WithExcludePaths(excludes))
	}
	src := container.New(args[0], opts...)

	return runScan(cmd, cfg, src, nil)
}

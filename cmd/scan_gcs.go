package cmd

import (
	"github.com/spf13/cobra"

	gcssource "github.com/HodeTech/leakwatch/internal/source/gcs"
)

var scanGCSCmd = &cobra.Command{
	Use:   "gcs <bucket>",
	Short: "Scans a Google Cloud Storage bucket",
	Long: `Scans objects in the specified GCS bucket to detect leaked secrets.
Uses Application Default Credentials for authentication.`,
	Example: `  # Scan an entire GCS bucket
  leakwatch scan gcs my-config-bucket

  # Scan only objects under a specific prefix
  leakwatch scan gcs my-bucket --prefix configs/production/

  # Scan with a specific GCP project
  leakwatch scan gcs my-bucket --project my-gcp-project

  # Output as CSV
  leakwatch scan gcs my-bucket --format csv --output gcs-results.csv`,
	Args: cobra.ExactArgs(1),
	RunE: runScanGCS,
}

func init() {
	scanCmd.AddCommand(scanGCSCmd)

	flags := scanGCSCmd.Flags()
	addCommonScanFlags(flags)
	addExcludePathFlag(flags)
	flags.String("prefix", "", "scan only objects with this key prefix")
	flags.String("project", "", "GCP project ID")

	addVerifyFlags(flags)
}

func runScanGCS(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	opts := []gcssource.Option{gcssource.WithMaxFileSize(cfg.MaxFileSize)}

	if excludes := mergedExcludePaths(cmd, cfg); len(excludes) > 0 {
		opts = append(opts, gcssource.WithExcludePaths(excludes))
	}

	if prefix := flagString(cmd, "prefix"); prefix != "" {
		opts = append(opts, gcssource.WithPrefix(prefix))
	}

	if project := flagString(cmd, "project"); project != "" {
		opts = append(opts, gcssource.WithProject(project))
	}

	cfg.ScanTarget = "gs://" + args[0]
	src := gcssource.New(args[0], opts...)

	return runScan(cmd, cfg, src, nil)
}

// Package cmd defines Leakwatch CLI commands.
// This package is a thin wiring layer; it must not contain business logic.
package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/meta"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a .leakwatch.yaml configuration file",
	Long: `Interactively creates a .leakwatch.yaml configuration file in the current
directory with recommended defaults. If a config file already exists, it will
ask before overwriting.`,
	Example: `  # Create config with defaults
  leakwatch init

  # Create config at specific path
  leakwatch init --output /path/to/.leakwatch.yaml`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().String("output", ".leakwatch.yaml", "output path for the config file")
	initCmd.Flags().Bool("force", false, "overwrite existing config file")
}

const defaultConfigTemplate = `# Leakwatch Configuration
# Documentation: https://github.com/HodeTech/Leakwatch/blob/main/docs/guides/configuration.md

scan:
  concurrency: 8          # Number of concurrent workers
  max-file-size: 10485760 # Maximum file size in bytes (10MB)

detection:
  entropy:
    enabled: true          # Enable Shannon entropy analysis
    threshold: 4.0         # Minimum entropy threshold

verification:
  enabled: true            # Enable secret verification via API
  rate-limit: 10           # Max verification requests per second
  timeout: 10s             # Per-request timeout

output:
  format: json             # Output format: {{OUTPUT_FORMATS}}
  show-raw: false          # Never show raw secret values

filter:
  exclude-paths:           # Paths to exclude from scanning
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "go.sum"
    - "package-lock.json"
    - "yarn.lock"

# Custom rules (uncomment to add your own detectors):
# custom-rules:
#   - id: "my-internal-token"
#     description: "Internal Service Token"
#     regex: "mycompany_[a-zA-Z0-9]{32}"
#     keywords: ["mycompany_"]
#     severity: critical
`

var defaultConfig = strings.Replace(defaultConfigTemplate, "{{OUTPUT_FORMATS}}", meta.OutputFormatList, 1)

func runInit(cmd *cobra.Command, _ []string) error {
	outputPath, err := cmd.Flags().GetString("output")
	if err != nil {
		return fmt.Errorf("failed to read output flag: %w", err)
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("failed to read force flag: %w", err)
	}

	cleanPath := filepath.Clean(outputPath)

	// Check if file already exists.
	if _, err := os.Stat(cleanPath); err == nil && !force {
		slog.Warn("config file already exists", "path", cleanPath)
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Config file %s already exists. Use --force to overwrite.\n", cleanPath)
		return fmt.Errorf("config file already exists: %s", cleanPath)
	}

	if err := os.WriteFile(cleanPath, []byte(defaultConfig), 0o644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created %s with recommended defaults.\n", cleanPath)
	return nil
}

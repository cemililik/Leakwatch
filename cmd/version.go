package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Shows Leakwatch version information",
	Example: `  leakwatch version`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Print(formatVersion(buildVersion, buildCommit, buildDate))
	},
}

func formatVersion(version, commit, date string) string {
	return fmt.Sprintf("leakwatch %s (commit: %s, built: %s)\n", version, commit, date)
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

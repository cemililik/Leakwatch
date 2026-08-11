package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	slacksource "github.com/HodeTech/leakwatch/internal/source/slack"
)

// flagIncludeFiles is the slack-only flag that requests scanning of uploaded
// file content. Defined as a constant so registration and read sites reference
// a single literal.
const flagIncludeFiles = "include-files"

// defaultSlackRateLimit is the source package's lowest-common-denominator Slack
// history limit (one request/minute). Marketplace/internal apps can raise it.
const defaultSlackRateLimit = slacksource.DefaultRateLimit

var scanSlackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scans a Slack workspace",
	Long: `Scans messages across channels in a Slack workspace to detect leaked secrets
such as API keys, passwords, and certificates. Text-like uploaded files can be
scanned with --include-files; downloads are size-bounded and restricted to
Slack-owned HTTPS endpoints.

Requires a Slack Bot Token with appropriate scopes (channels:history,
groups:history, im:history, mpim:history). File scanning additionally requires
files:read. The token can be provided via the --token flag or the
LEAKWATCH_SLACK_TOKEN environment variable.`,
	Example: `  # Scan all channels using environment variable for token
  export LEAKWATCH_SLACK_TOKEN=xoxb-your-token
  leakwatch scan slack

  # Scan specific channels
  leakwatch scan slack --token xoxb-... --channels general,engineering

  # Scan messages from the last 90 days
  leakwatch scan slack --since 2025-12-25

  # Exclude noisy channels
  leakwatch scan slack --exclude-channels random,social

  # Include direct messages
  leakwatch scan slack --include-dms

  # Include text-like file attachments (requires files:read)
  leakwatch scan slack --include-files --max-file-size 5242880

  # Use a higher rate for a Marketplace/internal app with Tier 3 history access
  leakwatch scan slack --rate-limit 0.8`,
	Args: cobra.NoArgs,
	RunE: runScanSlack,
}

func init() {
	scanCmd.AddCommand(scanSlackCmd)

	flags := scanSlackCmd.Flags()
	flags.String("token", "", "Slack Bot Token (or LEAKWATCH_SLACK_TOKEN env var)")
	flags.String("channels", "", "comma-separated channel names to scan (default: all)")
	flags.String("exclude-channels", "", "comma-separated channel names to exclude")
	flags.String("since", "", "scan messages after this date (YYYY-MM-DD)")
	flags.Bool("include-dms", false, "include direct messages")
	flags.Bool(flagIncludeFiles, false, "scan text-like uploaded files (requires files:read)")
	flags.Float64("rate-limit", defaultSlackRateLimit, "max Slack API requests per second")
	addCommonScanFlags(flags)
	addVerifyFlags(flags)
}

func runScanSlack(cmd *cobra.Command, _ []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	// Resolve token from flag, falling back to environment variable.
	token := flagString(cmd, "token")
	if token == "" {
		token = os.Getenv("LEAKWATCH_SLACK_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("slack bot token is required: use --token or set LEAKWATCH_SLACK_TOKEN")
	}

	opts := []slacksource.Option{slacksource.WithMaxFileSize(cfg.MaxFileSize)}

	if channels := flagString(cmd, "channels"); channels != "" {
		opts = append(opts, slacksource.WithChannels(splitComma(channels)))
	}

	if excludeChannels := flagString(cmd, "exclude-channels"); excludeChannels != "" {
		opts = append(opts, slacksource.WithExcludeChannels(splitComma(excludeChannels)))
	}

	if sinceStr := flagString(cmd, "since"); sinceStr != "" {
		since, err := time.Parse("2006-01-02", sinceStr)
		if err != nil {
			return fmt.Errorf("invalid --since date format, expected YYYY-MM-DD: %w", err)
		}
		opts = append(opts, slacksource.WithSince(since))
	}

	if flagBool(cmd, "include-dms") {
		opts = append(opts, slacksource.WithIncludeDMs(true))
	}

	if flagBool(cmd, flagIncludeFiles) {
		opts = append(opts, slacksource.WithIncludeFiles(true))
	}

	if rateLimit := flagFloat64(cmd, "rate-limit"); rateLimit > 0 {
		opts = append(opts, slacksource.WithRateLimit(rateLimit))
	}

	cfg.ScanTarget = "slack workspace"
	src := slacksource.New(token, opts...)

	return runScan(cmd, cfg, src, nil)
}

// splitComma splits a comma-separated string into trimmed, non-empty parts.
func splitComma(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

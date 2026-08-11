package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/HodeTech/leakwatch/internal/config"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/HodeTech/leakwatch/internal/output"
	csvout "github.com/HodeTech/leakwatch/internal/output/csv"
	githubout "github.com/HodeTech/leakwatch/internal/output/github"
	jsonout "github.com/HodeTech/leakwatch/internal/output/json"
	sarifout "github.com/HodeTech/leakwatch/internal/output/sarif"
	tableout "github.com/HodeTech/leakwatch/internal/output/table"
	"github.com/HodeTech/leakwatch/internal/scanner"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// defaultMaxFileSize is the default maximum size (in bytes) of a single
// file/blob/object Leakwatch reads into memory during a scan (10 MB). It is the
// single source of truth for every scan subcommand's --max-file-size default so
// the literal no longer has to be kept in sync by hand across seven files.
const defaultMaxFileSize = 10 * 1024 * 1024

// Flag names shared across the scan_*.go commands. Defining them as constants
// avoids duplicating the string literals that several commands reference when
// registering and reading the same flag.
const (
	flagShowRaw            = "show-raw"
	flagGrafanaInstanceURL = "grafana-instance-url"
	flagVerifierOrigin     = "verifier-origin"
)

// scanFlagBindings maps Viper config keys to the scan flag that overrides them.
// Each scan command's pflags are bound to a fresh, per-invocation Viper instance
// (see newScanViper) so that one command's flag defaults never leak into another
// command's resolved config. Binding a flag only takes effect when the user
// explicitly sets it; otherwise Viper falls back to env vars, the config file,
// and finally the registered defaults — preserving flag > env > file > default
// precedence. A flag that does not exist on a given command is skipped.
var scanFlagBindings = map[string]string{
	"scan.concurrency":   "concurrency",
	"scan.max-file-size": "max-file-size",
	"output.format":      "format",
	"output.file":        "output",
	"output.show-raw":    flagShowRaw,
}

// bindScanFlags binds the current command's common scan flags to the given,
// per-invocation Viper instance. Only flags present on the command are bound.
func bindScanFlags(v *viper.Viper, flags *pflag.FlagSet) {
	for key, flagName := range scanFlagBindings {
		f := flags.Lookup(flagName)
		if f == nil {
			continue
		}
		if err := v.BindPFlag(key, f); err != nil {
			slog.Warn("failed to bind scan flag", "flag", flagName, "error", err)
		}
	}
}

// newScanViper builds an isolated Viper instance for a single scan invocation.
// It performs the same config discovery the CLI uses globally (respecting the
// --config flag, otherwise searching the working directory and the home
// directory for .leakwatch.yaml), enables LEAKWATCH_-prefixed env var overrides
// with the same key replacer, and binds the active command's pflags so that
// flag > env > config-file > default precedence holds without cross-command
// global-state leakage (SYS-07a/b).
//
// A genuine config parse error (a malformed .leakwatch.yaml, or an explicit
// --config path that cannot be read) is fatal: it is returned as an error rather
// than warn-logged-and-ignored, so detection scope can never silently diverge
// from what the operator configured. A simply-absent config file on the search
// path is not an error.
func newScanViper(cmd *cobra.Command) (*viper.Viper, error) {
	v := viper.New()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName(".leakwatch")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
	}

	v.SetEnvPrefix("LEAKWATCH")
	// Map nested config keys to env vars: scan.concurrency -> LEAKWATCH_SCAN_CONCURRENCY,
	// output.severity-threshold -> LEAKWATCH_OUTPUT_SEVERITY_THRESHOLD.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		switch {
		case errors.As(err, &notFound):
			// No config file found on the search path: acceptable, use defaults.
		case errors.Is(err, os.ErrNotExist):
			// An explicit --config path that does not exist is treated as "no
			// config" (same as a search-path miss) rather than fatal.
			slog.Debug("config file not found", "file", v.ConfigFileUsed())
		default:
			// A genuine parse error (malformed YAML) or an otherwise-unreadable
			// config is fatal, so detection scope never silently diverges from
			// what the operator configured.
			return nil, fmt.Errorf("failed to parse config file %q: %w", v.ConfigFileUsed(), err)
		}
	}

	bindScanFlags(v, cmd.Flags())
	return v, nil
}

// addCommonScanFlags registers the format/output/concurrency/max-file-size/
// show-raw flags shared by every scan subcommand. It mirrors addVerifyFlags so a
// new subcommand cannot drift out of sync with the common flag surface, and it is
// the single place the --max-file-size default is wired.
func addCommonScanFlags(flags *pflag.FlagSet) {
	flags.StringP("format", "f", "json", "output format (json, sarif, csv, table, github)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers")
	flags.Int64("max-file-size", defaultMaxFileSize, "maximum file size in bytes")
	flags.Bool(flagShowRaw, false, "show raw secret content in output")
	flags.StringSlice("exclude-detectors", nil, "detector IDs to exclude (e.g. aws-access-key-id)")
}

// addExcludePathFlag registers the --exclude path-pattern flag. It is added to
// every source that supports path-based exclusion (fs/git/image/s3/gcs/repos, all
// of which accept WithExcludePaths); the Slack source deliberately omits it
// because it excludes by channel (--exclude-channels), not by path.
func addExcludePathFlag(flags *pflag.FlagSet) {
	flags.StringSlice("exclude", nil, "path patterns to exclude")
}

// addVerifyFlags adds the shared verification, severity, remediation, and
// command-line-only trusted-origin flags.
func addVerifyFlags(flags *pflag.FlagSet) {
	flags.Bool("no-verify", false, "disable secret verification")
	flags.Bool("only-verified", false, "only show verified active findings")
	flags.String("min-severity", "low", "minimum severity to report (low, medium, high, critical)")
	flags.Bool("remediation", false, "include remediation guidance in output")
	flags.String(flagGrafanaInstanceURL, "", "trusted Grafana instance origin for token verification (HTTPS; command-line only)")
	flags.StringArray(flagVerifierOrigin, nil, "trusted verifier origin as detector-id=https://host (repeatable; command-line only)")
}

// loadScanConfig loads and validates configuration for the active command using
// an isolated Viper instance whose only bound flags are this command's own. This
// guarantees that flags such as --concurrency, --max-file-size, and --format
// honor flag > env > config-file > default precedence without picking up another
// scan command's flag defaults (SYS-07a/b). Flags that are not config-keyed
// (--no-verify, --only-verified, --min-severity, --remediation, --exclude, and
// trusted verifier origins) are read directly from the command.
func loadScanConfig(cmd *cobra.Command) (*scanner.Config, error) {
	v, err := newScanViper(cmd)
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadFrom(v)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// The --min-severity flag takes precedence; fall back to the
	// output.severity-threshold config value only when the flag is not set. An
	// unrecognized value is rejected (rather than silently downgraded to "low")
	// using the same canonical severity set the config validator enforces.
	minSevStr := flagString(cmd, "min-severity")
	if !cmd.Flags().Changed("min-severity") && cfg.Output.SeverityThreshold != "" {
		minSevStr = cfg.Output.SeverityThreshold
	}
	minSev, ok := finding.ParseSeverity(minSevStr)
	if !ok {
		return nil, fmt.Errorf("invalid --min-severity value: %q (must be low, medium, high, or critical)", minSevStr)
	}

	// show-raw is bound to the isolated Viper, so cfg.Output.ShowRaw already
	// reflects flag > env > config > default. The explicit-set check lets
	// --show-raw=false override a config `show-raw: true` (OUT-m-04).
	showRaw := cfg.Output.ShowRaw
	if cmd.Flags().Changed(flagShowRaw) {
		showRaw = flagBool(cmd, flagShowRaw)
	}
	trustedOrigins, err := trustedVerifierOriginsFromFlags(cmd)
	if err != nil {
		return nil, err
	}

	return &scanner.Config{
		Concurrency:            cfg.Scan.Concurrency,
		MaxFileSize:            cfg.Scan.MaxFileSize,
		ExcludePaths:           cfg.Filter.ExcludePaths,
		ExcludeDetectors:       mergedExcludeDetectors(cmd, cfg),
		EnableEntropy:          cfg.Detection.Entropy.Enabled,
		EntropyThreshold:       cfg.Detection.Entropy.Threshold,
		ShowRaw:                showRaw,
		OutputFile:             cfg.Output.File,
		Format:                 cfg.Output.Format,
		NoVerify:               flagBool(cmd, "no-verify"),
		OnlyVerified:           flagBool(cmd, "only-verified"),
		MinSeverity:            minSev,
		EnableRemediation:      flagBool(cmd, "remediation"),
		VerifyEnabled:          cfg.Verification.Enabled,
		VerifyTimeout:          cfg.Verification.Timeout,
		VerifyConcurrency:      cfg.Verification.Concurrency,
		VerifyRateLimit:        cfg.Verification.RateLimit,
		GrafanaInstanceURL:     flagString(cmd, flagGrafanaInstanceURL),
		TrustedVerifierOrigins: trustedOrigins,
		CustomRules:            cfg.CustomRules,
	}, nil
}

func trustedVerifierOriginsFromFlags(cmd *cobra.Command) (map[string]string, error) {
	values := flagStringArray(cmd, flagVerifierOrigin)
	if len(values) == 0 {
		return nil, nil
	}
	origins := make(map[string]string, len(values))
	for _, value := range values {
		detectorID, origin, ok := strings.Cut(value, "=")
		detectorID = strings.TrimSpace(detectorID)
		origin = strings.TrimSpace(origin)
		if !ok || detectorID == "" || origin == "" {
			return nil, fmt.Errorf("invalid --%s value %q: expected detector-id=https://host", flagVerifierOrigin, value)
		}
		if _, duplicate := origins[detectorID]; duplicate {
			return nil, fmt.Errorf("duplicate --%s entry for detector %q", flagVerifierOrigin, detectorID)
		}
		origins[detectorID] = origin
	}
	return origins, nil
}

// mergedExcludeDetectors returns the config-file filter.exclude-detectors
// combined with any per-invocation --exclude-detectors flag values. Detector
// exclusion is otherwise config-file-only; wiring the flag here lets an operator
// suppress a noisy detector for a single run without editing .leakwatch.yaml
// (resolving the wave-3 carryover where the config key existed but no CLI flag
// did). The flag augments rather than replaces the config list.
func mergedExcludeDetectors(cmd *cobra.Command, cfg *config.Config) []string {
	flagVals := flagStringSlice(cmd, "exclude-detectors")
	if len(flagVals) == 0 {
		return cfg.Filter.ExcludeDetectors
	}
	merged := make([]string, 0, len(cfg.Filter.ExcludeDetectors)+len(flagVals))
	merged = append(merged, cfg.Filter.ExcludeDetectors...)
	merged = append(merged, flagVals...)
	return merged
}

// mergedExcludePaths returns the config-file exclude-paths combined with any
// per-invocation --exclude flag values registered by addCommonScanFlags. Every
// scan subcommand carries the flag, so exclusion works uniformly rather than
// being config-file-only on all sources but `scan fs`.
func mergedExcludePaths(cmd *cobra.Command, cfg *scanner.Config) []string {
	flagExcludes := flagStringSlice(cmd, "exclude")
	if len(flagExcludes) == 0 {
		return cfg.ExcludePaths
	}
	merged := make([]string, 0, len(cfg.ExcludePaths)+len(flagExcludes))
	merged = append(merged, cfg.ExcludePaths...)
	merged = append(merged, flagExcludes...)
	return merged
}

// runScan wires a single-source scan: it installs SIGINT/SIGTERM handling,
// delegates the scan pipeline to internal/scanner, renders the result, and maps
// an interruption to a distinct non-zero exit. If cl is non-nil its Close is
// called (best-effort) when the scan completes.
func runScan(cmd *cobra.Command, cfg *scanner.Config, src source.Source, cl io.Closer) error {
	if cl != nil {
		defer func() {
			if err := cl.Close(); err != nil {
				slog.Warn("failed to clean up source", "error", err)
			}
		}()
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	result, scanErr := scanner.Run(ctx, cfg, src)
	if result == nil {
		// Only a pre-scan failure (e.g. source validation) yields a nil result.
		return fmt.Errorf("scan failed: %w", scanErr)
	}
	return finishScan(cfg, result, src.Type(), scanErr)
}

// finishScan renders an already post-processed scan result and resolves the exit
// code. Exit-code contract (documented in Execute):
//   - findings present     -> FindingsExitError (exit 1)
//   - interrupted, no finds -> InterruptedExitError (exit 3): the scan did not
//     complete, so its clean verdict must not be trusted
//   - other scan error      -> wrapped error (exit 2)
//   - clean, complete       -> nil (exit 0)
//
// Findings take precedence over interruption so a "secrets found" signal is never
// masked, but an interrupted scan that found nothing can never report exit 0.
func finishScan(cfg *scanner.Config, result *engine.ScanResult, sourceType string, scanErr error) error {
	if err := writeOutput(cfg, result, sourceType); err != nil {
		return err
	}

	if len(result.Findings) > 0 {
		return &FindingsExitError{Count: len(result.Findings)}
	}
	if result.Interrupted {
		slog.Warn("scan did not complete before interruption; results are partial", "error", scanErr)
		return &InterruptedExitError{}
	}
	if scanErr != nil {
		return fmt.Errorf("scan failed: %w", scanErr)
	}
	return nil
}

// writeOutput renders the (already post-processed) findings to the configured
// destination using the selected formatter, then prints the scan summary to
// stderr. It returns only genuine output errors; the exit-code decision is made
// by finishScan. Both single-source scans and multi-repo scans funnel through
// here so their output behavior cannot drift (CMD-M-04).
func writeOutput(cfg *scanner.Config, result *engine.ScanResult, sourceType string) error {
	findings := result.Findings
	if findings == nil {
		findings = []finding.Finding{}
	}

	// The "github" format emits GitHub Actions workflow commands, which only take
	// effect on the live stdout stream — writing them to a file does nothing. If an
	// output file was configured (e.g. output.file in .leakwatch.yaml), ignore it
	// so the annotations always reach stdout instead of being silently swallowed.
	outputFile := cfg.OutputFile
	if cfg.Format == "github" && outputFile != "" {
		slog.Debug("ignoring output file for github format; annotations are written to stdout", "file", outputFile)
		outputFile = ""
	}

	colorEnabled := resolveColorEnabled(cfg.Format, outputFile)
	formatter := selectFormatter(cfg.Format, cfg.ShowRaw, colorEnabled)

	// Auto-suffix a bare --output path (one with no extension) with the
	// formatter's own extension, so `--format sarif --output results` writes
	// results.sarif rather than an extension-less file that downstream SARIF
	// consumers (e.g. GitHub Code Scanning) will not recognize.
	if outputFile != "" && filepath.Ext(outputFile) == "" {
		outputFile += formatter.FileExtension()
	}

	if outputFile != "" {
		if err := writeOutputFile(outputFile, formatter, findings); err != nil {
			return err
		}
	} else if err := formatter.Format(os.Stdout, findings); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Print scan summary to stderr (visible regardless of output format/file).
	printScanSummary(result, sourceType, cfg.ScanTarget)
	return nil
}

// writeOutputFile formats findings into the given path. The file is created with
// 0600 permissions because, under --show-raw, it can contain live secret values
// that must not be world/group-readable. The Close error is propagated on the
// success path: a swallowed Close can mean a silently truncated results file that
// a downstream CI consumer would trust. A deferred best-effort close only covers
// the early-return path where Format itself failed.
func writeOutputFile(path string, formatter output.Formatter, findings []finding.Finding) error {
	cleanPath := filepath.Clean(path)
	f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	if err := formatter.Format(f, findings); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write output: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to finalize output file: %w", err)
	}
	return nil
}

// selectFormatter returns the appropriate formatter based on the format string.
// When format is "table" and colorEnabled is true, ANSI color codes are used for severity.
func selectFormatter(format string, showRaw bool, colorEnabled bool) output.Formatter {
	switch format {
	case "sarif":
		// Version is the real build version (see cmd/root.go buildVersion) so
		// shipped SARIF documents are traceable to the release that produced
		// them instead of always reporting "dev".
		return &sarifout.Formatter{ShowRaw: showRaw, Version: buildVersion}
	case "csv":
		return &csvout.Formatter{ShowRaw: showRaw}
	case "table":
		return &tableout.Formatter{ShowRaw: showRaw, ColorEnabled: colorEnabled}
	case "github":
		// The GitHub annotations formatter intentionally ignores showRaw: it
		// only ever emits the redacted value, since annotations render in the
		// (often public) PR UI and run logs.
		return &githubout.Formatter{}
	default:
		return &jsonout.Formatter{ShowRaw: showRaw}
	}
}

// resolveColorEnabled decides whether ANSI color should be used for the given
// format/output destination by inspecting the real process environment: stdout
// must be a character device (a terminal, not a pipe/redirect) and the NO_COLOR
// convention (https://no-color.org) must not be set. It delegates the pure
// decision to shouldEnableColor so the policy can be unit-tested without a TTY.
func resolveColorEnabled(format, outputFile string) bool {
	_, noColor := os.LookupEnv("NO_COLOR")
	return shouldEnableColor(format, outputFile, stdoutIsTerminal(), noColor)
}

// shouldEnableColor is the pure color-policy decision: color is enabled only for
// table output written to stdout, when stdout is a terminal and NO_COLOR is unset.
func shouldEnableColor(format, outputFile string, stdoutIsTTY, noColor bool) bool {
	if format != "table" || outputFile != "" {
		return false
	}
	if noColor {
		return false
	}
	return stdoutIsTTY
}

// stdoutIsTerminal reports whether os.Stdout is connected to a terminal rather
// than a pipe or redirected file. It uses the ModeCharDevice bit from Stat so no
// extra dependency is required; pipes and regular files lack this bit, so ANSI
// escape sequences never leak into captured or redirected output (OUT-M-03).
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// printScanSummary writes scan metadata to stderr.
func printScanSummary(result *engine.ScanResult, sourceType string, target string) {
	fmt.Fprintf(os.Stderr, "\n── Scan Summary ─────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Date:            %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(os.Stderr, "  Source:          %s\n", sourceType)
	if target != "" {
		fmt.Fprintf(os.Stderr, "  Target:          %s\n", target)
	}
	fmt.Fprintf(os.Stderr, "  Files scanned:   %d\n", result.ScannedChunks)
	fmt.Fprintf(os.Stderr, "  Duration:        %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "  Findings:        %d\n", len(result.Findings))
	if result.Interrupted {
		fmt.Fprintf(os.Stderr, "  Status:          interrupted (partial results)\n")
	}
	fmt.Fprintf(os.Stderr, "─────────────────────────────────────────────────\n\n")
}

// flagString reads a string flag the active command is known to have registered.
// A lookup error is impossible for a registered flag of the right type; it is
// logged at Debug and the zero value returned rather than propagated, giving one
// consistent convention across cmd/ for these can't-happen lookups.
func flagString(cmd *cobra.Command, name string) string {
	v, err := cmd.Flags().GetString(name)
	if err != nil {
		slog.Debug("flag lookup failed", "flag", name, "error", err)
	}
	return v
}

// flagBool reads a bool flag; see flagString for the error convention.
func flagBool(cmd *cobra.Command, name string) bool {
	v, err := cmd.Flags().GetBool(name)
	if err != nil {
		slog.Debug("flag lookup failed", "flag", name, "error", err)
	}
	return v
}

// flagInt reads an int flag; see flagString for the error convention.
func flagInt(cmd *cobra.Command, name string) int {
	v, err := cmd.Flags().GetInt(name)
	if err != nil {
		slog.Debug("flag lookup failed", "flag", name, "error", err)
	}
	return v
}

// flagFloat64 reads a float64 flag; see flagString for the error convention.
func flagFloat64(cmd *cobra.Command, name string) float64 {
	v, err := cmd.Flags().GetFloat64(name)
	if err != nil {
		slog.Debug("flag lookup failed", "flag", name, "error", err)
	}
	return v
}

// flagStringSlice reads a string-slice flag; see flagString for the error
// convention.
func flagStringSlice(cmd *cobra.Command, name string) []string {
	v, err := cmd.Flags().GetStringSlice(name)
	if err != nil {
		slog.Debug("flag lookup failed", "flag", name, "error", err)
	}
	return v
}

// flagStringArray reads a repeatable string-array flag; see flagString for the
// error convention.
func flagStringArray(cmd *cobra.Command, name string) []string {
	v, err := cmd.Flags().GetStringArray(name)
	if err != nil {
		slog.Debug("flag lookup failed", "flag", name, "error", err)
	}
	return v
}

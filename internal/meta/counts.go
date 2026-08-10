// Package meta holds the canonical, human-maintained project counts that are
// published in the README banner, the social-preview image, and the docs.
//
// These constants are the single source of truth for the published numbers:
//
//   - Detectors and Verifiers are guarded at test time against the live
//     registries (detector.All() / verifier.All()), so adding or removing one
//     without updating the constant fails CI. See
//     internal/detector/registry_count_test.go and cmd/stats_test.go.
//   - Sources and OutputFormats change rarely and are golden values. They are
//     not derived at runtime on purpose: the scan command also exposes a
//     "repos" subcommand that is not a distinct source, and selectFormatter
//     accepts fallback aliases, so neither maps cleanly to a count.
//
// When any of these change, run `go generate ./...` to refresh the generated
// stat blocks in docs/assets/banner.html and site/assets/og.svg, then
// re-render their PNGs (the re-render command is in each asset's header).
package meta

//go:generate go run ./statsgen

const (
	// Detectors is the number of compile-time registered secret detectors;
	// it must equal len(detector.All()).
	Detectors = 65

	// Verifiers is the number of registered verifiers; it must equal
	// len(verifier.All()).
	Verifiers = 54

	// Sources is the number of scan sources: filesystem, git, container image,
	// S3, GCS, and Slack.
	Sources = 6

	// OutputFormats is the number of output formats: json, sarif, csv, table,
	// and github.
	OutputFormats = 5
)

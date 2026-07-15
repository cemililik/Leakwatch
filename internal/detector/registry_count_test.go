package detector_test

// This golden test pins the number of compile-time registered detectors so that
// accidentally dropping a detector (or a duplicate ID silently shadowing one)
// is caught immediately. It lives in the external detector_test package so it
// can blank-import every detector subpackage without creating an import cycle
// (each subpackage imports the detector package under test).
//
// Counts measured from the codebase:
//   - 63 detectors registered at compile time via init() (detector.Register).
//   - 59 packages register statically; azure, github, slack and stripe each
//     register two detectors (59 + 4 = 63).
//   - 60 detector subpackages exist in total; the 60th, "custom", registers its
//     rules at runtime (detector.RegisterIfAbsent) and is therefore not part of
//     the compile-time count.
//
// If you add or remove a detector, update internal/meta.Detectors (the single
// source of truth for the published count) and keep the blank-import block in
// sync with cmd/imports.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/meta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Each blank import runs the package's init(), registering its detector(s)
	// so the golden count below sees the full compile-time set. The per-line
	// comments mirror cmd/imports.go and satisfy the no-blank-import-without-
	// comment lint rule.
	_ "github.com/HodeTech/leakwatch/internal/detector/airtable"     // register airtable detector
	_ "github.com/HodeTech/leakwatch/internal/detector/anthropic"    // register anthropic detector
	_ "github.com/HodeTech/leakwatch/internal/detector/auth0"        // register auth0 detector
	_ "github.com/HodeTech/leakwatch/internal/detector/aws"          // register aws detector
	_ "github.com/HodeTech/leakwatch/internal/detector/azure"        // register azure detectors (storage + entra)
	_ "github.com/HodeTech/leakwatch/internal/detector/bitbucket"    // register bitbucket detector
	_ "github.com/HodeTech/leakwatch/internal/detector/circleci"     // register circleci detector
	_ "github.com/HodeTech/leakwatch/internal/detector/cloudflare"   // register cloudflare detector
	_ "github.com/HodeTech/leakwatch/internal/detector/coinbase"     // register coinbase detector
	_ "github.com/HodeTech/leakwatch/internal/detector/databricks"   // register databricks detector
	_ "github.com/HodeTech/leakwatch/internal/detector/datadog"      // register datadog detector
	_ "github.com/HodeTech/leakwatch/internal/detector/dbconn"       // register database connection-string detector
	_ "github.com/HodeTech/leakwatch/internal/detector/deepseek"     // register deepseek detector
	_ "github.com/HodeTech/leakwatch/internal/detector/digitalocean" // register digitalocean detector
	_ "github.com/HodeTech/leakwatch/internal/detector/discord"      // register discord detector
	_ "github.com/HodeTech/leakwatch/internal/detector/dockerhub"    // register dockerhub detector
	_ "github.com/HodeTech/leakwatch/internal/detector/doppler"      // register doppler detector
	_ "github.com/HodeTech/leakwatch/internal/detector/figma"        // register figma detector
	_ "github.com/HodeTech/leakwatch/internal/detector/ftp"          // register ftp credentials detector
	_ "github.com/HodeTech/leakwatch/internal/detector/gcp"          // register gcp service-account detector
	_ "github.com/HodeTech/leakwatch/internal/detector/generic"      // register generic api-key detector
	_ "github.com/HodeTech/leakwatch/internal/detector/github"       // register github detectors (pat + oauth)
	_ "github.com/HodeTech/leakwatch/internal/detector/gitlab"       // register gitlab detector
	_ "github.com/HodeTech/leakwatch/internal/detector/grafana"      // register grafana detector
	_ "github.com/HodeTech/leakwatch/internal/detector/heroku"       // register heroku detector
	_ "github.com/HodeTech/leakwatch/internal/detector/huggingface"  // register huggingface detector
	_ "github.com/HodeTech/leakwatch/internal/detector/infura"       // register infura detector
	_ "github.com/HodeTech/leakwatch/internal/detector/jwt"          // register jwt detector
	_ "github.com/HodeTech/leakwatch/internal/detector/launchdarkly" // register launchdarkly detector
	_ "github.com/HodeTech/leakwatch/internal/detector/ldap"         // register ldap credentials detector
	_ "github.com/HodeTech/leakwatch/internal/detector/linear"       // register linear detector
	_ "github.com/HodeTech/leakwatch/internal/detector/mailgun"      // register mailgun detector
	_ "github.com/HodeTech/leakwatch/internal/detector/newrelic"     // register newrelic detector
	_ "github.com/HodeTech/leakwatch/internal/detector/notion"       // register notion detector
	_ "github.com/HodeTech/leakwatch/internal/detector/npm"          // register npm detector
	_ "github.com/HodeTech/leakwatch/internal/detector/okta"         // register okta detector
	_ "github.com/HodeTech/leakwatch/internal/detector/openai"       // register openai detector
	_ "github.com/HodeTech/leakwatch/internal/detector/pagerduty"    // register pagerduty detector
	_ "github.com/HodeTech/leakwatch/internal/detector/postmark"     // register postmark detector
	_ "github.com/HodeTech/leakwatch/internal/detector/privatekey"   // register private-key detector (RSA, SSH, DSA, EC, PGP)
	_ "github.com/HodeTech/leakwatch/internal/detector/pypi"         // register pypi detector
	_ "github.com/HodeTech/leakwatch/internal/detector/rabbitmq"     // register rabbitmq detector
	_ "github.com/HodeTech/leakwatch/internal/detector/redis"        // register redis detector
	_ "github.com/HodeTech/leakwatch/internal/detector/rubygems"     // register rubygems detector
	_ "github.com/HodeTech/leakwatch/internal/detector/sendgrid"     // register sendgrid detector
	_ "github.com/HodeTech/leakwatch/internal/detector/sentry"       // register sentry detector
	_ "github.com/HodeTech/leakwatch/internal/detector/shopify"      // register shopify detector
	_ "github.com/HodeTech/leakwatch/internal/detector/slack"        // register slack detectors (token + webhook)
	_ "github.com/HodeTech/leakwatch/internal/detector/snowflake"    // register snowflake detector
	_ "github.com/HodeTech/leakwatch/internal/detector/snyk"         // register snyk detector
	_ "github.com/HodeTech/leakwatch/internal/detector/sonarcloud"   // register sonarcloud detector
	_ "github.com/HodeTech/leakwatch/internal/detector/stripe"       // register stripe detectors (live + test)
	_ "github.com/HodeTech/leakwatch/internal/detector/supabase"     // register supabase detector
	_ "github.com/HodeTech/leakwatch/internal/detector/teams"        // register microsoft teams webhook detector
	_ "github.com/HodeTech/leakwatch/internal/detector/telegram"     // register telegram detector
	_ "github.com/HodeTech/leakwatch/internal/detector/terraform"    // register terraform cloud detector
	_ "github.com/HodeTech/leakwatch/internal/detector/twilio"       // register twilio detector
	_ "github.com/HodeTech/leakwatch/internal/detector/vault"        // register hashicorp vault detector
	_ "github.com/HodeTech/leakwatch/internal/detector/vercel"       // register vercel detector
)

// registeredAtInit snapshots the registry right after every blank-imported
// detector package has run its init(), but before any test can mutate the
// global registry (the in-package registry_test.go calls detector.Reset()).
// Capturing here makes the golden assertion independent of test ordering.
var registeredAtInit []detector.Detector

func init() {
	registeredAtInit = detector.All()
}

func TestAll_RegisteredDetectorCount_MatchesGolden(t *testing.T) {
	assert.Len(t, registeredAtInit, meta.Detectors,
		"compile-time registered detector count drifted; update internal/meta.Detectors and cmd/imports.go together")

	// Every registered detector must have a unique, non-empty ID.
	ids := make(map[string]bool, len(registeredAtInit))
	for _, d := range registeredAtInit {
		assert.NotEmpty(t, d.ID())
		assert.False(t, ids[d.ID()], "duplicate detector ID: %s", d.ID())
		ids[d.ID()] = true
	}
}

// playgroundSkippedIDs are registered detectors intentionally absent from the
// generated site/js/detectors.js bundle. tools/site-build skips the "generic",
// "custom", and "testutil" detector packages because the in-browser regex
// scanner cannot reproduce their detection faithfully (see
// tools/site-build/detectors.go detectorSkipDirs). Of those, only the generic
// detector is registered at compile time, so it is the sole expected omission;
// "custom" registers at runtime (not in detector.All()) and "testutil" is a test
// helper, not a detector.
var playgroundSkippedIDs = map[string]bool{
	"generic-api-key": true,
}

// TestDetectorsJS_CoversEveryRegisteredDetector guards the generated playground
// bundle (site/js/detectors.js) against silently dropping a detector.
// tools/site-build extracts each detector's regex from the AST and emits a
// detector only when it finds a single regexp.MustCompile(`literal`); a pattern
// written as concatenated fragments, a const, or via fmt.Sprintf would vanish
// from the bundle while every other test still passes (the detector is still
// registered, so the golden count above is unaffected). This pins the bundle to
// the live registry so such a regression fails CI instead of silently shipping a
// gap in the web playground. See internal/detector/github/github_oauth.go for
// why that pattern is deliberately kept as one raw-string literal.
func TestDetectorsJS_CoversEveryRegisteredDetector(t *testing.T) {
	root, err := repoRoot()
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(root, "site", "js", "detectors.js"))
	require.NoError(t, err, "site/js/detectors.js missing; run `go run .` in tools/site-build")

	jsIDs := detectorIDsFromBundle(t, data)

	// Every registered detector (except the documented skips) must appear in the
	// bundle; a documented skip must NOT appear.
	for _, d := range registeredAtInit {
		if playgroundSkippedIDs[d.ID()] {
			assert.NotContains(t, jsIDs, d.ID(),
				"%q is in playgroundSkippedIDs but present in detectors.js; reconcile the skip set with tools/site-build detectorSkipDirs", d.ID())
			continue
		}
		assert.Contains(t, jsIDs, d.ID(),
			"detector %q is registered but missing from site/js/detectors.js; its regex is probably not a single regexp.MustCompile(`literal`) the extractor can read — keep the pattern AST-extractable and regenerate via tools/site-build", d.ID())
	}

	// The bundle must not list IDs for detectors that are not registered.
	registered := make(map[string]bool, len(registeredAtInit))
	for _, d := range registeredAtInit {
		registered[d.ID()] = true
	}
	for id := range jsIDs {
		assert.True(t, registered[id], "detectors.js lists %q which is not a registered detector (stale bundle?)", id)
	}
}

// detectorIDsFromBundle extracts the set of detector IDs from the JSON array
// embedded in the generated detectors.js (window.LW_DETECTORS = [ ... ];).
func detectorIDsFromBundle(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	start := bytes.IndexByte(data, '[')
	end := bytes.LastIndexByte(data, ']')
	require.True(t, start >= 0 && end > start, "detectors.js: could not locate the JSON array")

	var entries []struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(data[start:end+1], &entries))

	ids := make(map[string]bool, len(entries))
	for _, e := range entries {
		ids[e.ID] = true
	}
	return ids
}

// repoRoot walks up from the test working directory to the module root (the
// directory containing go.mod), so the test can read committed repo artifacts
// regardless of which package directory `go test` runs it from.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found searching upward from %s", dir)
		}
		dir = parent
	}
}

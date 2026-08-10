package remediation_test

// TestRemediation_AllDetectors_HaveRegisteredGuidance is the remediation-
// package counterpart of internal/meta's Detectors/Verifiers drift guard
// (cmd/stats_test.go's TestMetaCounts_MatchRuntime): it fails the build the
// moment a compile-time registered detector's ID has no matching
// remediation.Register call in guidance.go, catching the class of drift a
// manual cross-reference would otherwise silently miss the next time a
// detector is added.
//
// The blank imports below mirror cmd/imports.go's detector-registration
// block so detector.All() reflects the full, real detector set here too,
// without this package importing cmd (which would be a layering violation)
// or cmd importing remediation's test-only guard.
//
// The coverage check itself runs from an init() function (see below) rather
// than directly inside the Test function body: package-level init() funcs
// are guaranteed by the Go runtime to run to completion, in dependency
// order, before any Test* function executes. That makes the snapshot taken
// here immune to interference from remediation_test.go's own
// Register/Reset exercises of the (shared, package-level) registry, no
// matter what order the testing framework happens to run tests in.
import (
	"sort"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/remediation"
	"github.com/stretchr/testify/assert"

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
	_ "github.com/HodeTech/leakwatch/internal/detector/generic"      // register generic API-key and structured-config detectors
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

// missingGuidanceIDs is populated once, at package-init time, from the real
// detector.All() / remediation.Get() state, before any test in this package
// can call remediation.Reset().
var missingGuidanceIDs []string

func init() {
	for _, d := range detector.All() {
		if remediation.Get(d.ID()) == nil {
			missingGuidanceIDs = append(missingGuidanceIDs, d.ID())
		}
	}
	sort.Strings(missingGuidanceIDs)
}

func TestRemediation_AllDetectors_HaveRegisteredGuidance(t *testing.T) {
	assert.Empty(t, missingGuidanceIDs,
		"detector(s) with no registered remediation guidance (add a remediation.Register call in guidance.go): %v",
		missingGuidanceIDs)
}

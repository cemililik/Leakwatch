package cmd

// Blank imports below pull in the side effects of each plugin's init()
// function, which calls detector.Register / verifier.Register at compile
// time. This is the ADR-0004 plugin-registration pattern: the plugins are
// never referenced by name from the cmd package, so each import needs a
// per-line comment to make the intent explicit and to satisfy the
// "no-blank-import-without-comment" lint rule.

// Register detectors at compile time via init().
import (
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

// Register verifiers at compile time via init().
import (
	_ "github.com/HodeTech/leakwatch/internal/verifier/airtable"     // register airtable verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/anthropic"    // register anthropic verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/auth0"        // register auth0 verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/aws"          // register aws STS verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/azure"        // register azure verifiers (storage + entra)
	_ "github.com/HodeTech/leakwatch/internal/verifier/bitbucket"    // register bitbucket verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/circleci"     // register circleci verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/cloudflare"   // register cloudflare verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/coinbase"     // register coinbase verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/databricks"   // register databricks verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/datadog"      // register datadog verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/deepseek"     // register deepseek verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/digitalocean" // register digitalocean verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/discord"      // register discord verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/dockerhub"    // register dockerhub verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/doppler"      // register doppler verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/figma"        // register figma verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/gcp"          // register gcp verifier (format validation)
	_ "github.com/HodeTech/leakwatch/internal/verifier/github"       // register github verifiers (pat + oauth)
	_ "github.com/HodeTech/leakwatch/internal/verifier/gitlab"       // register gitlab verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/grafana"      // register grafana verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/heroku"       // register heroku verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/huggingface"  // register huggingface verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/infura"       // register infura verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/launchdarkly" // register launchdarkly verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/linear"       // register linear verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/mailgun"      // register mailgun verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/newrelic"     // register newrelic verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/notion"       // register notion verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/npm"          // register npm verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/okta"         // register okta verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/openai"       // register openai verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/pagerduty"    // register pagerduty verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/postmark"     // register postmark verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/pypi"         // register pypi verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/rabbitmq"     // register rabbitmq verifier (format validation)
	_ "github.com/HodeTech/leakwatch/internal/verifier/rubygems"     // register rubygems verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/sendgrid"     // register sendgrid verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/sentry"       // register sentry verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/shopify"      // register shopify verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/slack"        // register slack verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/snowflake"    // register snowflake verifier (format validation)
	_ "github.com/HodeTech/leakwatch/internal/verifier/snyk"         // register snyk verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/sonarcloud"   // register sonarcloud verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/stripe"       // register stripe verifiers (live + test)
	_ "github.com/HodeTech/leakwatch/internal/verifier/supabase"     // register supabase verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/teams"        // register microsoft teams webhook verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/telegram"     // register telegram verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/terraform"    // register terraform cloud verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/twilio"       // register twilio verifier
	_ "github.com/HodeTech/leakwatch/internal/verifier/vercel"       // register vercel verifier
)

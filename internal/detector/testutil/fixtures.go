package testutil

import "strings"

// DetectorContractFixture pins the observable contract of one canonical
// detector example. Expectations are deliberately explicit: a detector cannot
// widen Raw, drop an exact span, or move credential bytes into ExtraData while
// retaining a green registry-parity test.
type DetectorContractFixture struct {
	Input             []byte
	ExpectedRaw       []byte
	ExpectedRawV2     []byte
	ExpectedExtraData map[string]string
	// NonSecretRawExtraKeys explicitly documents rare fields where Raw is an
	// identifier rather than credential material (for example a GCP private key
	// ID) and may therefore also appear as non-secret verifier context.
	NonSecretRawExtraKeys map[string]bool
	RequireExactSpan      bool
}

// RegisteredDetectorFixtures returns one deliberately non-functional positive
// fixture for every compile-time detector. The catalog is shared by the
// registry-wide matcher test and detector-to-verifier contract test so neither
// layer can prove compatibility with hand-built RawFinding values that a real
// detector never emits.
func RegisteredDetectorFixtures() map[string]DetectorContractFixture {
	repeat := strings.Repeat
	assigned := func(prefix, raw string, span bool) DetectorContractFixture {
		return DetectorContractFixture{Input: []byte(prefix + raw), ExpectedRaw: []byte(raw), RequireExactSpan: span}
	}
	whole := func(input string) DetectorContractFixture {
		return DetectorContractFixture{Input: []byte(input), ExpectedRaw: []byte(input)}
	}
	paired := func(input, raw, rawV2 string, extra map[string]string, span bool) DetectorContractFixture {
		fixture := DetectorContractFixture{
			Input: []byte(input), ExpectedRaw: []byte(raw),
			ExpectedExtraData: extra, RequireExactSpan: span,
		}
		if rawV2 != "" {
			fixture.ExpectedRawV2 = []byte(rawV2)
		}
		return fixture
	}
	allowRawExtra := func(fixture DetectorContractFixture, keys ...string) DetectorContractFixture {
		fixture.NonSecretRawExtraKeys = make(map[string]bool, len(keys))
		for _, key := range keys {
			fixture.NonSecretRawExtraKeys[key] = true
		}
		return fixture
	}
	return map[string]DetectorContractFixture{
		"airtable-pat":      assigned("AIRTABLE_TOKEN=", "patAb12Cd34Ef56Gh."+repeat("ab12cd34", 8), false),
		"anthropic-api-key": assigned("ANTHROPIC_API_KEY=", "sk-ant-"+repeat("Ab12Cd34_", 10), false),
		"auth0-management-token": paired(
			"AUTH0_MANAGEMENT_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuZXUuYXV0aDAuY29tLyJ9.c2lnbmF0dXJlLWZpeHR1cmU",
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuZXUuYXV0aDAuY29tLyJ9.c2lnbmF0dXJlLWZpeHR1cmU",
			"AUTH0_MANAGEMENT_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuZXUuYXV0aDAuY29tLyJ9.c2lnbmF0dXJlLWZpeHR1cmU", nil, true,
		),
		"aws-access-key-id": paired(
			"aws_access_key_id=AKIAQ7M2PL9RT4VW8XYZ\naws_secret_access_key="+repeat("Ab1/", 10),
			"AKIAQ7M2PL9RT4VW8XYZ", repeat("Ab1/", 10), nil, false,
		),
		"azure-entra-secret": paired(
			"AZURE_CLIENT_SECRET="+repeat("Ab12Cd34", 5), repeat("Ab12Cd34", 5),
			"AZURE_CLIENT_SECRET="+repeat("Ab12Cd34", 5), nil, false,
		),
		"azure-storage-key": paired(
			"DefaultEndpointsProtocol=https;AccountName=syntheticacct;AccountKey="+repeat("Ab12Cd34", 11)+";",
			"DefaultEndpointsProtocol=https;AccountName=syntheticacct;AccountKey="+repeat("Ab12Cd34", 11)+";", "",
			map[string]string{"account_name": "syntheticacct"}, false,
		),
		"bitbucket-app-password": paired(
			"BITBUCKET_USERNAME=fixture-user\nBITBUCKET_APP_PASSWORD="+repeat("Ab12", 5),
			repeat("Ab12", 5), "BITBUCKET_APP_PASSWORD="+repeat("Ab12", 5),
			map[string]string{"username": "fixture-user"}, false,
		),
		"circleci-token": assigned("CIRCLECI_TOKEN=", "CCIPAT_"+repeat("Ab12Cd34_", 6), false),
		"cloudflare-api-token": paired(
			"CLOUDFLARE_API_TOKEN="+repeat("Ab12Cd34", 5), repeat("Ab12Cd34", 5),
			"CLOUDFLARE_API_TOKEN="+repeat("Ab12Cd34", 5), nil, false,
		),
		"coinbase-api-key": paired(
			"COINBASE_API_KEY="+repeat("Ab12Cd34", 4), repeat("Ab12Cd34", 4),
			"COINBASE_API_KEY="+repeat("Ab12Cd34", 4), nil, false,
		),
		"database-connection-string": whole("postgres://fixture_user:synthetic_password@db.example.invalid:5432/app"),
		"databricks-token": paired(
			"DATABRICKS_HOST=https://fixture.cloud.databricks.com\nDATABRICKS_TOKEN=dapi"+repeat("ab12cd34", 4),
			"dapi"+repeat("ab12cd34", 4), "", map[string]string{"host": "https://fixture.cloud.databricks.com"}, false,
		),
		"datadog-api-key": paired(
			"DATADOG_API_KEY="+repeat("ab12cd34", 4), repeat("ab12cd34", 4),
			"DATADOG_API_KEY="+repeat("ab12cd34", 4), nil, false,
		),
		"deepseek-api-key":   assigned("DEEPSEEK_API_KEY=", "sk-"+repeat("ab12cd34", 4), false),
		"digitalocean-token": assigned("DIGITALOCEAN_TOKEN=", "dop_v1_"+repeat("ab12cd34", 8), false),
		"discord-bot-token":  assigned("DISCORD_TOKEN=", "M"+repeat("Ab1c", 5)+"Xyz.Ab1Cd2."+repeat("Abc1", 6)+"XyZ", false),
		"discord-webhook-url": paired(
			"https://discord.com/api/webhooks/123456789012345678/"+repeat("Ab12Cd34_", 4),
			"discord.com/api/webhooks/123456789012345678/"+repeat("Ab12Cd34_", 4), "", nil, false,
		),
		"dockerhub-pat":   assigned("DOCKER_TOKEN=", "dckr_pat_"+repeat("Ab12Cd34_", 4), false),
		"doppler-token":   assigned("DOPPLER_TOKEN=", "dp.st."+repeat("Ab12Cd34_", 5), false),
		"figma-pat":       assigned("FIGMA_TOKEN=", "figd_"+repeat("Ab12Cd34_", 5), false),
		"ftp-credentials": whole("ftp://fixture-user:synthetic-password@ftp.example.invalid:21/uploads"),
		"gcp-service-account": allowRawExtra(paired(
			`{"type":"service_account","project_id":"fixture-project","private_key_id":"abcdef1234567890abcdef1234567890abcdef12","client_email":"fixture@fixture-project.iam.gserviceaccount.com"}`,
			"abcdef1234567890abcdef1234567890abcdef12",
			`{"type":"service_account","project_id":"fixture-project","private_key_id":"abcdef1234567890abcdef1234567890abcdef12","client_email":"fixture@fixture-project.iam.gserviceaccount.com"}`,
			map[string]string{"client_email": "fixture@fixture-project.iam.gserviceaccount.com", "private_key_id": "abcdef1234567890abcdef1234567890abcdef12"}, false,
		), "private_key_id"),
		"generic-api-key": paired(
			`api_key = "Q7mN2pL9rT4vW8xYzC6bH3kF"`, "Q7mN2pL9rT4vW8xYzC6bH3kF", "",
			map[string]string{"key_name": "api_key"}, true,
		),
		"github-oauth-token": paired(
			"GITHUB_TOKEN=gho_"+repeat("Ab12Cd34_", 4), "gho_"+repeat("Ab12Cd34_", 4), "",
			map[string]string{"token_subtype": "gho"}, false,
		),
		"github-token":          assigned("GITHUB_TOKEN=", "ghp_"+repeat("Ab12Cd34_", 4), false),
		"gitlab-pat":            assigned("GITLAB_TOKEN=", "glpat-"+repeat("Ab12Cd34_", 3), false),
		"grafana-api-key":       assigned("GRAFANA_TOKEN=", "glsa_"+repeat("Ab12Cd34", 4)+"_abcdef12", false),
		"hashicorp-vault-token": assigned("VAULT_TOKEN=", "hvs."+repeat("Ab12Cd34_", 3), false),
		"heroku-api-key": paired(
			"HEROKU_API_KEY=12345678-1234-abcd-9876-1234567890ab", "12345678-1234-abcd-9876-1234567890ab",
			"HEROKU_API_KEY=12345678-1234-abcd-9876-1234567890ab", nil, false,
		),
		"huggingface-token": assigned("HF_TOKEN=", "hf_"+repeat("Ab12Cd34", 5), false),
		"infura-api-key": paired(
			"INFURA_API_KEY="+repeat("ab12cd34", 4), repeat("ab12cd34", 4),
			"INFURA_API_KEY="+repeat("ab12cd34", 4), nil, false,
		),
		"jwt":                  assigned("Authorization: Bearer ", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."+repeat("Ab12Cd34", 4), false),
		"launchdarkly-sdk-key": assigned("LAUNCHDARKLY_SDK_KEY=", "sdk-abcdef01-2345-6789-abcd-0123456789ab", false),
		"ldap-credentials":     whole("ldaps://fixture-user:synthetic-password@ldap.example.invalid:636/dc=example,dc=invalid"),
		"linear-api-key":       assigned("LINEAR_API_KEY=", "lin_api_"+repeat("Ab12Cd34", 5), false),
		"mailgun-api-key":      assigned("MAILGUN_API_KEY=", "key-"+repeat("ab12cd34", 4), false),
		"newrelic-api-key":     assigned("NEW_RELIC_API_KEY=", "NRAK-"+repeat("AB12CD34X", 3), false),
		"notion-token":         assigned("NOTION_TOKEN=", "ntn_"+repeat("Ab12Cd34", 6), false),
		"npm-token":            assigned("NPM_TOKEN=", "npm_"+repeat("Ab12Cd34X", 4), false),
		"okta-api-token": paired(
			"OKTA_ORG=https://fixture.okta.com\nAuthorization: SSWS 00"+repeat("Ab12Cd34", 5),
			"00"+repeat("Ab12Cd34", 5), "", map[string]string{"domain": "fixture.okta.com"}, false,
		),
		"openai-api-key":        assigned("OPENAI_API_KEY=", "sk-proj-"+repeat("Ab12Cd34_", 6), false),
		"pagerduty-api-key":     assigned("PAGERDUTY_API_KEY=", "u+"+repeat("Ab12Cd34_", 3), false),
		"postmark-server-token": assigned("POSTMARK_SERVER_TOKEN=", "abcdef01-2345-6789-abcd-0123456789ab", false),
		"private-key": paired(
			"-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-KEY-MATERIAL\n-----END PRIVATE KEY-----",
			"-----BEGIN PRIVATE KEY-----", "", map[string]string{"block_bytes": "80"}, false,
		),
		"pypi-api-token":             assigned("PYPI_TOKEN=", "pypi-AgEIcHlwaS5vcmc"+repeat("Ab12Cd34_", 7), false),
		"rabbitmq-connection-string": whole("amqps://fixture-user:synthetic-password@rabbitmq.example.invalid:5671/vhost"),
		"redis-connection-string":    whole("rediss://fixture-user:synthetic-password@cache.example.invalid:6380/0"),
		"rubygems-api-key":           assigned("RUBYGEMS_API_KEY=", "rubygems_"+repeat("ab12cd34", 6), false),
		"sendgrid-api-key":           assigned("SENDGRID_API_KEY=", "SG."+repeat("Ab", 11)+"."+repeat("Ab", 21)+"A", false),
		"sentry-token":               assigned("SENTRY_AUTH_TOKEN=", "sntrys_"+repeat("Ab12Cd34_", 5), false),
		"shopify-access-token":       assigned("SHOPIFY_ACCESS_TOKEN=", "shpat_"+repeat("ab12cd34", 4), true),
		"slack-token":                assigned("SLACK_TOKEN=", "xoxb-123456789012-123456789012-"+repeat("Ab12Cd34", 3), false),
		"slack-webhook":              whole("https://hooks.slack.com/services/TABCDEF12/BABCDEF12/" + repeat("Ab12Cd34", 3)),
		"snowflake-credentials": paired(
			"account.snowflakecomputing.com/?warehouse=fixture&password=synthetic-password",
			"synthetic-password", "snowflakecomputing.com/?warehouse=fixture&password=synthetic-password", nil, false,
		),
		"snyk-api-key":        assigned("SNYK_TOKEN=", "abcdef01-2345-6789-abcd-0123456789ab", false),
		"sonarcloud-token":    assigned("SONAR_TOKEN=", "sqp_"+repeat("ab12cd34", 5), false),
		"stripe-api-key-live": assigned("STRIPE_SECRET_KEY=", "sk_live_"+repeat("Ab12Cd34", 3), false),
		"stripe-api-key-test": assigned("STRIPE_TEST_KEY=", "sk_test_"+repeat("Ab12Cd34", 3), false),
		"structured-config-secret": paired(
			`{"Database":{"Password":"Q7mN2pL9rT4vW8xYzC6bH3kF"}}`, "Q7mN2pL9rT4vW8xYzC6bH3kF", "",
			map[string]string{"key_name": "Password", "key_path": "Database.Password", "config_format": "json"}, true,
		),
		"supabase-service-key":  assigned("SUPABASE_ACCESS_TOKEN=", "sbp_"+repeat("ab12cd34", 5), false),
		"teams-webhook":         whole("https://fixture.webhook.office.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/IncomingWebhook/abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789"),
		"telegram-bot-token":    assigned("TELEGRAM_BOT_TOKEN=", "123456789:"+repeat("Ab12Cd3", 5), false),
		"terraform-cloud-token": assigned("TERRAFORM_TOKEN=", repeat("Ab12Cd3", 2)+".atlasv1."+repeat("Ab12Cd34", 9), false),
		"twilio-api-key": paired(
			"TWILIO_API_KEY_SID=SK"+repeat("ab12cd34", 4)+"\nTWILIO_API_KEY_SECRET=synthetic-opaque-value-Ab12Cd34",
			"synthetic-opaque-value-Ab12Cd34", "", map[string]string{"api_key_sid": "SK" + repeat("ab12cd34", 4)}, true,
		),
		"vercel-token": assigned("VERCEL_TOKEN=", "vercel_"+repeat("Ab12Cd34_", 3), false),
	}
}

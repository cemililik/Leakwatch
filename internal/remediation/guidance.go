package remediation

import "github.com/HodeTech/leakwatch/pkg/finding"

// Reusable step and checklist strings to keep guidance consistent and
// minimize duplication across providers.
const (
	stepUpdateIntegrationsToken = "Update all integrations with the new token."
	stepUpdateIntegrationsKey   = "Update all integrations with the new key."
	stepUpdateCICDToken         = "Update CI/CD pipelines with the new token."
	stepDeleteCompromisedToken  = "Delete the compromised token."
	stepDeleteCompromisedKey    = "Delete the compromised key."
	stepDeleteOldAPIKey         = "Delete the old API key."
	stepRevokeCompromisedToken  = "Revoke the compromised token."
	stepCreateNewAPIKey         = "Create a new API key."
	stepCreateNewToken          = "Create a new token."
	stepCreateNewKey            = "Create a new key."

	checkNotifySecurityTeam = "Notify the security team about the exposure."
	checkNotifyTeam         = "Notify the team about the exposure."
	checkScanCodebaseForKey = "Scan the codebase for other occurrences of the same key."
)

func init() {
	Register("aws-access-key-id", finding.Remediation{
		Title: "Rotate AWS Access Key",
		Steps: []string{
			"Sign in to the AWS IAM console and locate the compromised access key.",
			"Create a new access key for the same IAM user.",
			"Update all services, applications, and CI/CD pipelines that use the old key.",
			"Deactivate the old access key and monitor CloudTrail for any usage.",
			"Delete the old access key after confirming no remaining usage.",
		},
		DocURL:     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys_console",
		ConsoleURL: "https://console.aws.amazon.com/iam/home#/security_credentials",
		Urgency:    "immediate",
		Checklist: []string{
			"Review CloudTrail logs for unauthorized usage of the compromised key.",
			"Check for any resources created or modified by the compromised key.",
			checkNotifySecurityTeam,
			checkScanCodebaseForKey,
		},
	})

	Register("github-token", finding.Remediation{
		Title: "Revoke GitHub Token",
		Steps: []string{
			"Go to GitHub Settings > Developer settings > Personal access tokens.",
			"Revoke the compromised token immediately.",
			"Create a new token with the minimum required scopes.",
			"Update all integrations and CI/CD pipelines with the new token.",
		},
		DocURL:     "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
		ConsoleURL: "https://github.com/settings/tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Review the GitHub audit log for unauthorized actions performed with the token.",
			"Check repository and organization settings for unexpected changes.",
			checkNotifySecurityTeam,
			"Scan for other repositories that may contain the same token.",
		},
	})

	Register("slack-token", finding.Remediation{
		Title: "Revoke Slack Token",
		Steps: []string{
			"Go to Slack App Management at api.slack.com/apps.",
			"Select the affected application and navigate to OAuth & Permissions.",
			"Revoke the compromised bot or user token.",
			"Reinstall the app to generate a new token.",
			"Update all services using the old token.",
		},
		DocURL:     "https://api.slack.com/authentication/rotation",
		ConsoleURL: "https://api.slack.com/apps",
		Urgency:    "high",
		Checklist: []string{
			"Review Slack access logs for unauthorized message reads or posts.",
			"Check for any data exfiltration from private channels.",
			"Notify the workspace administrators about the exposure.",
			"Scan for other locations where the token may be stored.",
		},
	})

	Register("slack-webhook", finding.Remediation{
		Title: "Regenerate Slack Webhook URL",
		Steps: []string{
			"Go to Slack App Management at api.slack.com/apps.",
			"Select the affected application and navigate to Incoming Webhooks.",
			"Remove the compromised webhook URL.",
			"Create a new webhook URL for the target channel.",
			"Update all services that post via the old webhook URL.",
		},
		DocURL:     "https://api.slack.com/messaging/webhooks",
		ConsoleURL: "https://api.slack.com/apps",
		Urgency:    "high",
		Checklist: []string{
			"Review the target channel for unexpected or malicious messages.",
			"Notify the channel members about potential spam from the compromised webhook.",
			"Scan for other locations where the webhook URL may be stored.",
		},
	})

	Register("stripe-api-key-live", finding.Remediation{
		Title: "Roll Stripe Live API Key",
		Steps: []string{
			"Sign in to the Stripe Dashboard and go to Developers > API keys.",
			"Roll the compromised live secret key to generate a new one.",
			"Update all backend services and payment integrations with the new key.",
			"Monitor the Stripe Dashboard for any unauthorized transactions.",
		},
		DocURL:     "https://docs.stripe.com/keys#rolling-keys",
		ConsoleURL: "https://dashboard.stripe.com/apikeys",
		Urgency:    "immediate",
		Checklist: []string{
			"Review recent Stripe events and logs for unauthorized charges or refunds.",
			"Check for any new connected accounts or transfers.",
			"Notify the security and finance teams about the exposure.",
			checkScanCodebaseForKey,
		},
	})

	Register("stripe-api-key-test", finding.Remediation{
		Title: "Roll Stripe Test API Key",
		Steps: []string{
			"Sign in to the Stripe Dashboard and go to Developers > API keys.",
			"Roll the compromised test secret key to generate a new one.",
			"Update development and staging environments with the new key.",
		},
		DocURL:     "https://docs.stripe.com/keys#rolling-keys",
		ConsoleURL: "https://dashboard.stripe.com/test/apikeys",
		Urgency:    "medium",
		Checklist: []string{
			"Verify no live data was accessible through the test key.",
			"Update CI/CD pipelines that reference the old test key.",
			"Scan for other locations where the test key may be stored.",
		},
	})

	Register("jwt", finding.Remediation{
		Title: "Rotate JWT Signing Key",
		Steps: []string{
			"Generate a new signing key (symmetric secret or asymmetric key pair).",
			"Deploy the new key to all services that issue or validate tokens.",
			"Invalidate all existing tokens by revoking sessions or using a deny list.",
			"Monitor authentication logs for tokens signed with the old key.",
		},
		DocURL:     "https://datatracker.ietf.org/doc/html/rfc7519",
		ConsoleURL: "",
		Urgency:    "high",
		Checklist: []string{
			"Identify all services and clients that consume the JWT.",
			"Check authentication logs for unauthorized access using the leaked token.",
			checkNotifySecurityTeam,
			"Verify that token expiration and refresh mechanisms are properly configured.",
		},
	})

	Register("database-connection-string", finding.Remediation{
		Title: "Rotate Database Credentials",
		Steps: []string{
			"Change the database user password immediately via your database management tool.",
			"Update all application connection configurations with the new password.",
			"Restart services that use pooled connections to pick up the new credentials.",
			"Review database access logs for unauthorized connections.",
			"Consider restricting the database user's permissions to the minimum required.",
		},
		DocURL:     "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check database audit logs for unauthorized queries or data exports.",
			"Verify that network-level access controls (firewall, security groups) are in place.",
			"Notify the security team and database administrators about the exposure.",
			"Scan for other locations where the connection string may be stored.",
		},
	})

	Register("private-key", finding.Remediation{
		Title: "Regenerate Private Key",
		Steps: []string{
			"Generate a new key pair using a strong algorithm (e.g., Ed25519 or RSA 4096).",
			"Revoke any certificates signed by the compromised key.",
			"Remove the compromised public key from all authorized_keys and trust stores.",
			"Deploy the new public key to all systems and services.",
			"Securely delete the compromised private key from all storage locations.",
		},
		DocURL:     "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Review SSH and TLS access logs for unauthorized connections using the compromised key.",
			"Check certificate transparency logs if the key was used for TLS.",
			checkNotifySecurityTeam,
			"Audit all systems where the key had access.",
		},
	})

	Register("generic-api-key", finding.Remediation{
		Title: "Rotate API Key",
		Steps: []string{
			"Identify the service provider associated with the API key.",
			"Sign in to the provider's dashboard and locate the API key management section.",
			"Revoke or regenerate the compromised key.",
			"Update all services and integrations with the new key.",
		},
		DocURL:     "",
		ConsoleURL: "",
		Urgency:    "high",
		Checklist: []string{
			"Review the provider's usage and audit logs for unauthorized API calls.",
			checkNotifySecurityTeam,
			checkScanCodebaseForKey,
			"Consider using a secrets manager to avoid embedding keys in source code.",
		},
	})

	Register("structured-config-secret", finding.Remediation{
		Title: "Move Configuration Secret to Secure Storage",
		Steps: []string{
			"Treat the exposed value as compromised and rotate or revoke it at its owning service.",
			"Remove the plaintext value from the configuration file and its version history.",
			"Store the replacement in a secrets manager or the platform's protected local-secret mechanism.",
			"Reference the protected value through environment or secret-manager indirection.",
			"Redeploy affected services and verify that the old credential no longer works.",
		},
		DocURL:  "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
		Urgency: "immediate",
		Checklist: []string{
			"Review repository, artifact, backup, log, and chat history for additional copies.",
			"Audit the owning service for unauthorized use of the exposed credential.",
			checkNotifySecurityTeam,
			checkScanCodebaseForKey,
		},
	})

	Register("openai-api-key", finding.Remediation{
		Title: "Rotate OpenAI API Key",
		Steps: []string{
			"Go to platform.openai.com/api-keys.",
			stepCreateNewAPIKey,
			stepUpdateIntegrationsKey,
			stepDeleteOldAPIKey,
			"Check usage logs for unauthorized activity.",
		},
		DocURL:     "https://platform.openai.com/docs/guides/safety-best-practices",
		ConsoleURL: "https://platform.openai.com/api-keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check billing for unauthorized usage.",
			"Review API logs for suspicious activity.",
			checkNotifyTeam,
		},
	})

	Register("anthropic-api-key", finding.Remediation{
		Title: "Rotate Anthropic API Key",
		Steps: []string{
			"Go to console.anthropic.com/settings/keys.",
			stepCreateNewAPIKey,
			stepUpdateIntegrationsKey,
			stepDeleteOldAPIKey,
		},
		DocURL:     "https://docs.anthropic.com/en/docs/initial-setup",
		ConsoleURL: "https://console.anthropic.com/settings/keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check usage logs for unauthorized activity.",
			"Review billing for unexpected charges.",
			checkNotifyTeam,
		},
	})

	Register("gitlab-pat", finding.Remediation{
		Title: "Revoke GitLab Personal Access Token",
		Steps: []string{
			"Go to GitLab Settings > Access Tokens.",
			stepRevokeCompromisedToken,
			"Create a new token with minimal scopes.",
			stepUpdateCICDToken,
		},
		DocURL:     "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html",
		ConsoleURL: "https://gitlab.com/-/user_settings/personal_access_tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Check repository activity for unauthorized changes.",
			"Review CI/CD jobs for suspicious runs.",
			"Audit access logs for unauthorized access.",
		},
	})

	Register("sendgrid-api-key", finding.Remediation{
		Title: "Rotate SendGrid API Key",
		Steps: []string{
			"Go to SendGrid Settings > API Keys.",
			"Create a new key with minimal permissions.",
			"Update email service configuration with the new key.",
			stepDeleteOldAPIKey,
		},
		DocURL:     "https://docs.sendgrid.com/ui/account-and-settings/api-keys",
		ConsoleURL: "https://app.sendgrid.com/settings/api_keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check sent email logs for abuse.",
			"Monitor bounce and spam rates for anomalies.",
			checkNotifyTeam,
		},
	})

	Register("npm-token", finding.Remediation{
		Title: "Revoke NPM Access Token",
		Steps: []string{
			"Run `npm token revoke <token>` or go to npmjs.com > Access Tokens.",
			stepCreateNewToken,
			stepUpdateCICDToken,
			"Check for unauthorized package publishes.",
		},
		DocURL:     "https://docs.npmjs.com/about-access-tokens",
		ConsoleURL: "https://www.npmjs.com/settings/~/tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Check for unauthorized package publishes.",
			"Review download stats for anomalies.",
			"Run npm audit on affected packages.",
		},
	})

	Register("datadog-api-key", finding.Remediation{
		Title: "Rotate Datadog API Key",
		Steps: []string{
			"Go to Datadog Organization Settings > API Keys.",
			stepCreateNewAPIKey,
			"Update DD_API_KEY in all deployments.",
			stepDeleteOldAPIKey,
		},
		DocURL:     "https://docs.datadoghq.com/account_management/api-app-keys/",
		ConsoleURL: "https://app.datadoghq.com/organization-settings/api-keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check Datadog audit trail.",
			"Review metric submissions.",
			"Notify SRE team.",
		},
	})

	Register("discord-bot-token", finding.Remediation{
		Title: "Reset Discord Bot Token",
		Steps: []string{
			"Go to Discord Developer Portal.",
			"Select your application.",
			"Navigate to Bot settings.",
			"Click Reset Token.",
			"Update all bot configurations.",
		},
		DocURL:     "https://discord.com/developers/docs/reference",
		ConsoleURL: "https://discord.com/developers/applications",
		Urgency:    "immediate",
		Checklist: []string{
			"Check bot activity logs.",
			"Review server permissions.",
			"Notify server admins.",
		},
	})

	Register("discord-webhook-url", finding.Remediation{
		Title: "Delete and Recreate Discord Webhook",
		Steps: []string{
			"Open the Discord server and go to the channel's Integrations settings.",
			"Locate the exposed webhook under Webhooks.",
			"Delete the webhook to invalidate the leaked URL immediately.",
			"Create a new webhook and store its URL in a secret manager.",
			"Update every integration that posted through the old webhook.",
		},
		DocURL:     "https://discord.com/developers/docs/resources/webhook",
		ConsoleURL: "https://discord.com/developers/applications",
		Urgency:    "immediate",
		Checklist: []string{
			"Review the channel's message history for unauthorized posts.",
			"Audit which integrations held the old webhook URL.",
			"Confirm the old webhook URL returns 404 after deletion.",
		},
	})

	Register("redis-connection-string", finding.Remediation{
		Title: "Rotate Redis Credentials",
		Steps: []string{
			"Connect to Redis.",
			"Create new user/password with ACL SETUSER.",
			"Update all application configs.",
			"Remove old credentials with ACL DELUSER.",
		},
		DocURL:     "https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check Redis MONITOR for unauthorized access.",
			"Review connected clients.",
			"Flush suspicious sessions.",
		},
	})

	Register("snowflake-credentials", finding.Remediation{
		Title: "Rotate Snowflake Password",
		Steps: []string{
			"Log in to Snowflake.",
			"ALTER USER to change password.",
			"Update all JDBC connection strings.",
			"Revoke active sessions with ALTER USER ABORT ALL QUERIES.",
		},
		DocURL:     "https://docs.snowflake.com/en/sql-reference/sql/alter-user",
		ConsoleURL: "https://app.snowflake.com",
		Urgency:    "immediate",
		Checklist: []string{
			"Review QUERY_HISTORY for unauthorized access.",
			"Check ACCESS_HISTORY.",
			"Notify data team.",
		},
	})

	Register("telegram-bot-token", finding.Remediation{
		Title: "Revoke Telegram Bot Token",
		Steps: []string{
			"Open Telegram.",
			"Message @BotFather.",
			"Use /revoke command.",
			"Select the bot.",
			"Create new token with /token.",
			"Update integrations.",
		},
		DocURL:     "https://core.telegram.org/bots/api",
		ConsoleURL: "https://t.me/BotFather",
		Urgency:    "immediate",
		Checklist: []string{
			"Check bot message history.",
			"Review webhook configurations.",
			"Notify team.",
		},
	})

	// Sprint 2 detectors

	Register("huggingface-token", finding.Remediation{
		Title: "Revoke Hugging Face Token",
		Steps: []string{
			"Go to huggingface.co/settings/tokens.",
			stepDeleteCompromisedToken,
			stepCreateNewToken,
		},
		DocURL:     "https://huggingface.co/docs/hub/security-tokens",
		ConsoleURL: "",
		Urgency:    "immediate",
	})

	Register("deepseek-api-key", finding.Remediation{
		Title: "Rotate DeepSeek API Key",
		Steps: []string{
			"Go to platform.deepseek.com, API Keys section.",
			stepDeleteCompromisedKey,
			stepCreateNewAPIKey,
		},
		DocURL:     "https://platform.deepseek.com/api-docs",
		ConsoleURL: "",
		Urgency:    "immediate",
	})

	Register("gcp-service-account", finding.Remediation{
		Title: "Rotate GCP Service Account Key",
		Steps: []string{
			"Go to GCP Console > IAM > Service Accounts.",
			stepDeleteCompromisedKey,
			stepCreateNewKey,
			"Update all deployments with the new key.",
		},
		DocURL:     "https://cloud.google.com/iam/docs/keys-create-delete",
		ConsoleURL: "https://console.cloud.google.com/iam-admin/serviceaccounts",
		Urgency:    "immediate",
		Checklist: []string{
			"Check Cloud Audit Logs.",
			"Review IAM permissions.",
			"Notify security team.",
		},
	})

	Register("azure-storage-key", finding.Remediation{
		Title: "Rotate Azure Storage Access Key",
		Steps: []string{
			"Go to Azure Portal > Storage Account > Access Keys.",
			"Rotate the compromised key.",
			"Update all connection strings.",
		},
		DocURL:     "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check Storage Analytics logs.",
			"Review SAS tokens derived from key.",
		},
	})

	Register("azure-entra-secret", finding.Remediation{
		Title: "Rotate Azure Entra ID Client Secret",
		Steps: []string{
			"Go to Azure Portal > App Registrations > Certificates & Secrets.",
			"Delete the old secret.",
			"Create a new client secret.",
			"Update all applications with the new secret.",
		},
		DocURL:     "https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal",
		ConsoleURL: "",
		Urgency:    "immediate",
	})

	Register("okta-api-token", finding.Remediation{
		Title: "Revoke Okta API Token",
		Steps: []string{
			"Go to Okta Admin Console > Security > API > Tokens.",
			stepRevokeCompromisedToken,
		},
		DocURL:     "https://developer.okta.com/docs/guides/create-an-api-token",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Review system log for unauthorized API calls.",
		},
	})

	Register("twilio-api-key", finding.Remediation{
		Title: "Rotate Twilio API Key Pair",
		Steps: []string{
			"Go to Twilio Console > API Keys.",
			"Identify the API Key SID paired with the exposed secret and revoke that key.",
			stepCreateNewAPIKey,
		},
		DocURL:     "https://www.twilio.com/docs/iam/api-keys",
		ConsoleURL: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
		Urgency:    "immediate",
		Checklist: []string{
			"Check call/SMS logs for abuse.",
		},
	})

	Register("mailgun-api-key", finding.Remediation{
		Title: "Rotate Mailgun API Key",
		Steps: []string{
			"Go to Mailgun Dashboard > API Keys.",
			stepCreateNewKey,
			"Update all integrations.",
			"Delete the old key.",
		},
		DocURL:     "https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check sending logs for unauthorized emails.",
		},
	})

	Register("hashicorp-vault-token", finding.Remediation{
		Title: "Revoke Vault Token",
		Steps: []string{
			"Run `vault token revoke <token>` or revoke via API.",
		},
		DocURL:     "https://developer.hashicorp.com/vault/docs/commands/token/revoke",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check Vault audit logs.",
			"Review token policies.",
		},
	})

	Register("grafana-api-key", finding.Remediation{
		Title: "Revoke Grafana Service Account Token",
		Steps: []string{
			"Go to Grafana > Administration > Service Accounts.",
			stepDeleteCompromisedToken,
		},
		DocURL:     "https://grafana.com/docs/grafana/latest/administration/service-accounts/",
		ConsoleURL: "",
		Urgency:    "high",
	})

	Register("pagerduty-api-key", finding.Remediation{
		Title: "Rotate PagerDuty API Key",
		Steps: []string{
			"Go to PagerDuty > My Profile > User Settings > API Access.",
			stepCreateNewKey,
			"Delete the old key.",
		},
		DocURL:     "https://support.pagerduty.com/docs/api-access-keys",
		ConsoleURL: "",
		Urgency:    "high",
	})

	Register("circleci-token", finding.Remediation{
		Title: "Revoke CircleCI Token",
		Steps: []string{
			"Go to CircleCI > User Settings > Personal API Tokens.",
			stepDeleteCompromisedToken,
		},
		DocURL:     "https://circleci.com/docs/managing-api-tokens/",
		ConsoleURL: "",
		Urgency:    "high",
	})

	Register("github-oauth-token", finding.Remediation{
		Title: "Revoke GitHub OAuth Token",
		Steps: []string{
			"Go to GitHub Settings > Developer Settings > OAuth Apps.",
			stepRevokeCompromisedToken,
		},
		DocURL:     "https://docs.github.com/en/apps/oauth-apps",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check GitHub audit log.",
			"Review app permissions.",
		},
	})

	// Sprint 3 detectors

	Register("pypi-api-token", finding.Remediation{
		Title: "Revoke PyPI API Token",
		Steps: []string{
			"Go to pypi.org > Account Settings > API Tokens.",
			stepDeleteCompromisedToken,
			"Create a new scoped token with minimal permissions.",
			stepUpdateCICDToken,
		},
		DocURL:     "https://pypi.org/help/#apitoken",
		ConsoleURL: "https://pypi.org/manage/account/#api-tokens",
		Urgency:    "immediate",
	})

	Register("rubygems-api-key", finding.Remediation{
		Title: "Revoke RubyGems API Key",
		Steps: []string{
			"Go to rubygems.org > Settings > API Keys.",
			stepDeleteCompromisedKey,
			"Create a new API key with minimal scopes.",
			"Update CI/CD pipelines with the new key.",
		},
		DocURL:     "https://guides.rubygems.org/api-key-scopes/",
		ConsoleURL: "https://rubygems.org/settings/edit",
		Urgency:    "immediate",
		Checklist: []string{
			"Check for unauthorized gem publishes.",
		},
	})

	Register("dockerhub-pat", finding.Remediation{
		Title: "Revoke Docker Hub PAT",
		Steps: []string{
			"Go to hub.docker.com > Account Settings > Security.",
			"Delete the compromised personal access token.",
			"Create a new token with appropriate permissions.",
			"Update all Docker CLI and CI/CD configurations.",
		},
		DocURL:     "https://docs.docker.com/security/for-developers/access-tokens/",
		ConsoleURL: "https://hub.docker.com/settings/security",
		Urgency:    "immediate",
		Checklist: []string{
			"Check image push history for unauthorized publishes.",
		},
	})

	Register("digitalocean-token", finding.Remediation{
		Title: "Revoke DigitalOcean Token",
		Steps: []string{
			"Go to cloud.digitalocean.com > API > Tokens.",
			stepDeleteCompromisedToken,
			"Create a new token with required scopes.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://docs.digitalocean.com/reference/api/",
		ConsoleURL: "https://cloud.digitalocean.com/account/api/tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Check droplet/resource activity for unauthorized changes.",
		},
	})

	Register("heroku-api-key", finding.Remediation{
		Title: "Regenerate Heroku API Key",
		Steps: []string{
			"Go to dashboard.heroku.com > Account Settings.",
			"Regenerate the API key.",
			"Update all CLI sessions and CI/CD pipelines with the new key.",
		},
		DocURL:     "https://devcenter.heroku.com/articles/authentication",
		ConsoleURL: "https://dashboard.heroku.com/account",
		Urgency:    "immediate",
	})

	Register("vercel-token", finding.Remediation{
		Title: "Revoke Vercel Token",
		Steps: []string{
			"Go to vercel.com > Settings > Tokens.",
			stepDeleteCompromisedToken,
			stepCreateNewToken,
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://vercel.com/docs/rest-api",
		ConsoleURL: "https://vercel.com/account/tokens",
		Urgency:    "high",
	})

	Register("newrelic-api-key", finding.Remediation{
		Title: "Delete New Relic API Key",
		Steps: []string{
			"Go to one.newrelic.com > API Keys.",
			stepDeleteCompromisedKey,
			stepCreateNewAPIKey,
			stepUpdateIntegrationsKey,
		},
		DocURL:     "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/",
		ConsoleURL: "https://one.newrelic.com/api-keys",
		Urgency:    "high",
	})

	Register("sentry-token", finding.Remediation{
		Title: "Revoke Sentry Auth Token",
		Steps: []string{
			"Go to sentry.io > Settings > Auth Tokens.",
			stepDeleteCompromisedToken,
			"Create a new auth token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://docs.sentry.io/api/auth/",
		ConsoleURL: "https://sentry.io/settings/account/api/auth-tokens/",
		Urgency:    "high",
	})

	Register("shopify-access-token", finding.Remediation{
		Title: "Rotate Shopify Access Token",
		Steps: []string{
			"Go to Shopify Admin > Settings > Apps and sales channels > Develop apps.",
			"Open the affected app and revoke or rotate the compromised Admin API access token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://shopify.dev/docs/apps/auth",
		ConsoleURL: "",
		Urgency:    "immediate",
		Checklist: []string{
			"Check order/customer data access for unauthorized activity.",
		},
	})

	Register("supabase-service-key", finding.Remediation{
		Title: "Revoke Supabase Personal Access Token",
		Steps: []string{
			"Open the Supabase Dashboard account access-token page.",
			"Identify and revoke the compromised personal access token.",
			"Create a replacement only if the CLI or automation still requires one, then update those consumers.",
		},
		DocURL:     "https://supabase.com/docs/reference/api/introduction",
		ConsoleURL: "https://supabase.com/dashboard/account/tokens",
		Urgency:    "immediate",
	})

	Register("cloudflare-api-token", finding.Remediation{
		Title: "Revoke Cloudflare API Token",
		Steps: []string{
			"Go to dash.cloudflare.com > My Profile > API Tokens.",
			stepDeleteCompromisedToken,
			"Create a new token with minimal permissions.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://developers.cloudflare.com/api/tokens/create/",
		ConsoleURL: "https://dash.cloudflare.com/profile/api-tokens",
		Urgency:    "immediate",
		Checklist: []string{
			"Check DNS changes and firewall rules for unauthorized modifications.",
		},
	})

	Register("notion-token", finding.Remediation{
		Title: "Revoke Notion Integration Token",
		Steps: []string{
			"Go to notion.so > Settings > Connections > Develop or manage integrations.",
			"Revoke the compromised integration token.",
			"Create a new integration secret.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://developers.notion.com/docs/authorization",
		ConsoleURL: "https://www.notion.so/my-integrations",
		Urgency:    "high",
	})

	Register("linear-api-key", finding.Remediation{
		Title: "Revoke Linear API Key",
		Steps: []string{
			"Go to linear.app > Settings > API.",
			stepDeleteCompromisedKey,
			stepCreateNewAPIKey,
			stepUpdateIntegrationsKey,
		},
		DocURL:     "https://developers.linear.app/docs/graphql/working-with-the-graphql-api",
		ConsoleURL: "https://linear.app/settings/api",
		Urgency:    "high",
	})

	Register("figma-pat", finding.Remediation{
		Title: "Revoke Figma PAT",
		Steps: []string{
			"Go to figma.com > Settings > Personal Access Tokens.",
			stepDeleteCompromisedToken,
			"Create a new personal access token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://www.figma.com/developers/api#access-tokens",
		ConsoleURL: "https://www.figma.com/settings",
		Urgency:    "high",
	})

	Register("airtable-pat", finding.Remediation{
		Title: "Revoke Airtable PAT",
		Steps: []string{
			"Go to airtable.com > Account > Developer hub > Personal access tokens.",
			stepDeleteCompromisedToken,
			"Create a new personal access token with minimal scopes.",
			stepUpdateIntegrationsToken,
		},
		DocURL:     "https://airtable.com/developers/web/guides/personal-access-tokens",
		ConsoleURL: "https://airtable.com/create/tokens",
		Urgency:    "high",
	})

	// Sprint 4 detectors

	Register("terraform-cloud-token", finding.Remediation{
		Title: "Revoke Terraform Cloud Token",
		Steps: []string{
			"Go to app.terraform.io > User Settings > Tokens.",
			stepDeleteCompromisedToken,
			stepCreateNewToken,
			stepUpdateIntegrationsToken,
		},
		DocURL:  "https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/api-tokens",
		Urgency: "immediate",
	})

	Register("databricks-token", finding.Remediation{
		Title: "Revoke Databricks PAT",
		Steps: []string{
			"Go to Databricks workspace > User Settings > Access Tokens.",
			stepRevokeCompromisedToken,
			"Create a new personal access token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:  "https://docs.databricks.com/en/dev-tools/auth/pat.html",
		Urgency: "immediate",
	})

	Register("bitbucket-app-password", finding.Remediation{
		Title: "Revoke Bitbucket App Password",
		Steps: []string{
			"Go to bitbucket.org > Personal Settings > App passwords.",
			"Revoke the compromised app password.",
			"Create a new app password with minimal permissions.",
			"Update all integrations with the new password.",
		},
		DocURL:  "https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/",
		Urgency: "immediate",
	})

	Register("coinbase-api-key", finding.Remediation{
		Title: "Rotate Coinbase API Key",
		Steps: []string{
			"Go to coinbase.com > Settings > API.",
			"Delete the compromised API key.",
			"Create a new API key with minimal permissions.",
			stepUpdateIntegrationsKey,
		},
		DocURL:  "https://docs.cdp.coinbase.com/coinbase-app/docs/getting-started",
		Urgency: "immediate",
		Checklist: []string{
			"Check transaction history for unauthorized activity.",
		},
	})

	Register("infura-api-key", finding.Remediation{
		Title: "Rotate Infura API Key",
		Steps: []string{
			"Go to app.infura.io > Project Settings.",
			"Regenerate the compromised API key.",
			stepUpdateIntegrationsKey,
		},
		DocURL:  "https://docs.infura.io/api/getting-started",
		Urgency: "high",
	})

	Register("rabbitmq-connection-string", finding.Remediation{
		Title: "Rotate RabbitMQ Credentials",
		Steps: []string{
			"Access RabbitMQ management UI or use rabbitmqctl.",
			"Change the compromised user password.",
			"Update all application connection strings.",
			"Restart consumers to pick up new credentials.",
		},
		DocURL:  "https://www.rabbitmq.com/docs/passwords",
		Urgency: "immediate",
	})

	Register("ftp-credentials", finding.Remediation{
		Title: "Change FTP/SFTP Password",
		Steps: []string{
			"Access the server admin panel or FTP server configuration.",
			"Change the compromised FTP/SFTP password.",
			"Update all clients and scripts using the old credentials.",
		},
		Urgency: "immediate",
		Checklist: []string{
			"Check FTP logs for unauthorized access.",
		},
	})

	Register("ldap-credentials", finding.Remediation{
		Title: "Change LDAP Bind Password",
		Steps: []string{
			"Access the LDAP admin console.",
			"Change the bind DN password.",
			"Update all applications using the old bind credentials.",
		},
		DocURL:  "https://ldap.com/ldapv3-wire-protocol-reference-bind/",
		Urgency: "immediate",
	})

	Register("auth0-management-token", finding.Remediation{
		Title: "Revoke Auth0 Token",
		Steps: []string{
			"Go to Auth0 Dashboard > Applications.",
			"Rotate the client secret or revoke the management API token.",
			"Update all integrations with the new credentials.",
		},
		DocURL:  "https://auth0.com/docs/secure/tokens/management-api-access-tokens",
		Urgency: "immediate",
	})

	Register("launchdarkly-sdk-key", finding.Remediation{
		Title: "Rotate LaunchDarkly SDK Key",
		Steps: []string{
			"Go to LaunchDarkly dashboard > Account Settings > Projects.",
			"Reset the compromised SDK key.",
			stepUpdateIntegrationsKey,
		},
		DocURL:  "https://docs.launchdarkly.com/sdk/concepts/client-side-server-side",
		Urgency: "high",
	})

	Register("snyk-api-key", finding.Remediation{
		Title: "Revoke Snyk Token",
		Steps: []string{
			"Go to app.snyk.io > Account Settings > API Token.",
			stepRevokeCompromisedToken,
			"Generate a new API token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:  "https://docs.snyk.io/snyk-api/authentication-for-api",
		Urgency: "high",
	})

	Register("sonarcloud-token", finding.Remediation{
		Title: "Revoke SonarCloud Token",
		Steps: []string{
			"Go to sonarcloud.io > My Account > Security.",
			stepRevokeCompromisedToken,
			"Generate a new token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:  "https://docs.sonarsource.com/sonarcloud/advanced-setup/user-accounts/generating-and-using-tokens/",
		Urgency: "high",
	})

	Register("doppler-token", finding.Remediation{
		Title: "Revoke Doppler Service Token",
		Steps: []string{
			"Go to dashboard.doppler.com > Project > Service Tokens.",
			"Delete the compromised service token.",
			"Create a new service token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:  "https://docs.doppler.com/docs/service-tokens",
		Urgency: "immediate",
	})

	Register("teams-webhook", finding.Remediation{
		Title: "Delete Teams Webhook",
		Steps: []string{
			"Go to Teams channel > Connectors > Incoming Webhook.",
			"Remove the compromised webhook.",
			"Create a new incoming webhook if needed.",
			"Update all integrations with the new webhook URL.",
		},
		DocURL:  "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
		Urgency: "high",
	})

	Register("postmark-server-token", finding.Remediation{
		Title: "Rotate Postmark Server Token",
		Steps: []string{
			"Go to account.postmarkapp.com > Servers > API Tokens.",
			"Regenerate the compromised server token.",
			stepUpdateIntegrationsToken,
		},
		DocURL:  "https://postmarkapp.com/developer/api/overview",
		Urgency: "high",
	})
}

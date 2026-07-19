package discord

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// discordWebhookPattern matches Discord webhook URLs
// (discord(app).com/api/webhooks/<id>/<token>), a secret class distinct from
// bot tokens: frequently hardcoded in CI scripts and client-side code, and
// immediately abusable for spam/exfiltration once leaked.
var discordWebhookPattern = regexp.MustCompile(`discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+`)

// WebhookDetector detects Discord Webhook URLs. It lives alongside the bot
// token Detector in this package (rather than a separate package) since both
// are Discord-specific secret shapes; see azure's StorageDetector/EntraDetector
// for the same one-package-multiple-detectors convention.
type WebhookDetector struct{}

// ID returns the unique identifier of the Discord Webhook URL detector.
func (d *WebhookDetector) ID() string { return "discord-webhook-url" }

// Description returns a human-readable description of the Discord Webhook URL detector.
func (d *WebhookDetector) Description() string { return "Discord Webhook URL" }

// Keywords returns the Aho-Corasick pre-filter keywords for Discord Webhook URL detection.
func (d *WebhookDetector) Keywords() []string {
	return []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"}
}

// Severity returns the default severity level for Discord Webhook URL findings.
func (d *WebhookDetector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Discord Webhook URL patterns.
func (d *WebhookDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := discordWebhookPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&WebhookDetector{})
}

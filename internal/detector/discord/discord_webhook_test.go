package discord

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhookDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &WebhookDetector{}
	assert.Equal(t, "discord-webhook-url", d.ID())
	assert.Equal(t, "Discord Webhook URL", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestWebhookDetector_Scan_MatchesValidWebhooks(t *testing.T) {
	// Synthetic webhook ID/token — no real Discord webhook material.
	syntheticToken := strings.Repeat("Ab1Cd2Ef3", 5)

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "discord.com webhook URL",
			input:    "https://discord.com/api/webhooks/123456789012345678/" + syntheticToken,
			expected: 1,
		},
		{
			name:     "discordapp.com legacy domain webhook URL",
			input:    "https://discordapp.com/api/webhooks/987654321098765432/" + syntheticToken,
			expected: 1,
		},
		{
			name:     "webhook URL embedded in CI script",
			input:    `curl -X POST "https://discord.com/api/webhooks/111111111111111111/` + syntheticToken + `"`,
			expected: 1,
		},
		{
			name: "multiple webhook URLs",
			input: "https://discord.com/api/webhooks/111111111111111111/" + syntheticToken +
				" https://discordapp.com/api/webhooks/222222222222222222/" + syntheticToken,
			expected: 2,
		},
	}

	d := &WebhookDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 {
				require.NotEmpty(t, findings)
				assert.Equal(t, "discord-webhook-url", findings[0].DetectorID)
				assert.NotContains(t, findings[0].Redacted, syntheticToken, "redacted value must not contain the full token")
			}
		})
	}
}

func TestWebhookDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "discord.com URL that is not a webhook endpoint",
			input: "https://discord.com/channels/123456789012345678",
		},
		{
			name:  "webhook path with non-numeric ID",
			input: "https://discord.com/api/webhooks/not-a-number/" + strings.Repeat("Ab1Cd2Ef3", 5),
		},
		{
			name:  "unrelated domain",
			input: "https://example.com/api/webhooks/123456789012345678/" + strings.Repeat("Ab1Cd2Ef3", 5),
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &WebhookDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

// TestWebhookDetector_Scan_RawIsClonedNotAliased verifies Raw does not alias
// the scanned chunk buffer (memory/aliasing hardening).
func TestWebhookDetector_Scan_RawIsClonedNotAliased(t *testing.T) {
	data := []byte("https://discord.com/api/webhooks/123456789012345678/" + strings.Repeat("Ab1Cd2Ef3", 5))

	d := &WebhookDetector{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawBefore := string(findings[0].Raw)
	for i := range data {
		data[i] = 'x'
	}
	assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
}

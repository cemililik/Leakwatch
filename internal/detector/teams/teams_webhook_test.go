package teams

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "teams-webhook", d.ID())
	assert.Equal(t, "Microsoft Teams Incoming Webhook URL", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidWebhooks(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid teams webhook URL",
			input:    "https://mycompany.webhook.office.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/IncomingWebhook/abcdef0123456789abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789",
			expected: 1,
			redacted: "https://mycompany.webhook.office.com/webhookb2/****",
		},
		{
			name:     "webhook in config",
			input:    `TEAMS_WEBHOOK="https://tenant-name.webhook.office.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/IncomingWebhook/abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789"`,
			expected: 1,
			redacted: "https://tenant-name.webhook.office.com/webhookb2/****",
		},
		{
			name:     "webhook with hyphenated subdomain",
			input:    "https://my-org-name.webhook.office.com/webhookb2/12345678-abcd-1234-abcd-123456789abc/IncomingWebhook/abcdef0123456789/12345678-abcd-1234-abcd-123456789abc",
			expected: 1,
		},
		{
			name:     "webhook in large text",
			input:    strings.Repeat("x", 10000) + "https://mycompany.webhook.office.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/IncomingWebhook/abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789" + strings.Repeat("y", 10000),
			expected: 1,
		},
		{
			name:     "multiple webhooks",
			input:    "https://a.webhook.office.com/webhookb2/11111111-1111-1111-1111-111111111111/IncomingWebhook/aaaa1111bbbb2222/11111111-1111-1111-1111-111111111111 https://b.webhook.office.com/webhookb2/22222222-2222-2222-2222-222222222222/IncomingWebhook/cccc3333dddd4444/22222222-2222-2222-2222-222222222222",
			expected: 2,
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

func TestDetector_Scan_Redacted_DistinguishesDifferentSubdomains(t *testing.T) {
	input := "https://tenant-a.webhook.office.com/webhookb2/11111111-1111-1111-1111-111111111111/IncomingWebhook/aaaa1111bbbb2222/11111111-1111-1111-1111-111111111111 https://tenant-b.webhook.office.com/webhookb2/22222222-2222-2222-2222-222222222222/IncomingWebhook/cccc3333dddd4444/22222222-2222-2222-2222-222222222222"

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(input))
	require.Len(t, findings, 2)

	// Two genuinely different webhooks must not render identically in output.
	assert.NotEqual(t, findings[0].Redacted, findings[1].Redacted)
	assert.Equal(t, "https://tenant-a.webhook.office.com/webhookb2/****", findings[0].Redacted)
	assert.Equal(t, "https://tenant-b.webhook.office.com/webhookb2/****", findings[1].Redacted)
}

func TestDetector_Scan_Raw_DoesNotAliasInputBuffer(t *testing.T) {
	input := []byte("https://mycompany.webhook.office.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/IncomingWebhook/abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789")

	d := &Detector{}
	findings := d.Scan(context.Background(), input)
	require.Len(t, findings, 1)

	raw := findings[0].Raw
	original := string(raw)

	for i := range input {
		input[i] = 'x'
	}

	assert.Equal(t, original, string(raw))
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong domain",
			input: "https://mycompany.webhook.example.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/IncomingWebhook/abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789",
		},
		{
			name:  "missing IncomingWebhook path",
			input: "https://mycompany.webhook.office.com/webhookb2/abcdef01-2345-6789-abcd-ef0123456789/OutgoingWebhook/abcdef0123456789/abcdef01-2345-6789-abcd-ef0123456789",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "partial URL",
			input: "https://mycompany.webhook.office.com/webhookb2/",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

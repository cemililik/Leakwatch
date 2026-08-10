package generic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/dbconn"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructuredConfigDetector_Metadata(t *testing.T) {
	d := &StructuredConfigDetector{}
	assert.Equal(t, "structured-config-secret", d.ID())
	assert.Equal(t, "Structured Configuration Secret", d.Description())
	assert.NotEmpty(t, d.Keywords())
}

func TestStructuredConfigDetector_AppsettingsFixture(t *testing.T) {
	data := readSyntheticAppsettings(t)
	d := &StructuredConfigDetector{}

	direct := d.Scan(context.Background(), data)
	viaMatcher := testutil.ScanViaMatcher(d, data)
	require.Equal(t, direct, viaMatcher)
	require.Len(t, direct, 4)

	wantPaths := []string{
		"XHCPClientCredentials.ClientSecret",
		"BTradePrivateApiCredentials.Password",
		"GtpSettings.Password",
		"ElasticApm.SecretToken",
	}
	gotPaths := make([]string, 0, len(direct))
	for _, got := range direct {
		gotPaths = append(gotPaths, got.ExtraData["key_path"])
		assert.Equal(t, "json", got.ExtraData["config_format"])
		assert.Equal(t, string(got.Raw), string(data[got.ByteStart:got.ByteEnd]))
		assert.NotEqual(t, string(got.Raw), got.Redacted)
	}
	assert.Equal(t, wantPaths, gotPaths)
}

func TestStructuredConfigDetector_AppsettingsFullEngine_EightLocationsSixValues(t *testing.T) {
	data := readSyntheticAppsettings(t)
	detectors := []detector.Detector{
		&dbconn.ConnectionString{},
		&APIKeyDetector{},
		&StructuredConfigDetector{},
	}
	eng := engine.New(engine.Config{
		Concurrency:      3,
		Detectors:        detectors,
		EnableEntropy:    true,
		EntropyThreshold: 4.0,
	})

	result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
	require.NoError(t, err)
	require.Len(t, result.Findings, 8, "fixture must produce one finding per secret-bearing location without overlap duplicates")

	lines := make([]int, 0, len(result.Findings))
	counts := make(map[string]int)
	for _, got := range result.Findings {
		lines = append(lines, got.SourceMetadata.Line)
		counts[got.DetectorID]++
		assert.Empty(t, got.Raw, "default engine output must not expose fixture values")
	}
	assert.Equal(t, []int{3, 7, 11, 31, 37, 43, 49, 52}, lines)
	assert.Equal(t, map[string]int{
		"database-connection-string": 1,
		"generic-api-key":            3,
		"structured-config-secret":   4,
	}, counts)

	unique := make(map[string]struct{})
	for _, det := range detectors {
		for _, raw := range det.Scan(context.Background(), data) {
			unique[string(raw.Raw)] = struct{}{}
		}
	}
	assert.Len(t, unique, 6, "three APISIX locations intentionally share one synthetic value")
}

func TestStructuredConfigDetector_HardNegatives(t *testing.T) {
	data := []byte(`{
  "ClientId": "client-identifier-123456",
  "Username": "service-account-name",
  "PublicKey": "public-key-identifier",
  "PasswordHash": "9mN2pQ7rT4vW8xY0zA1bC5dF",
  "PasswordResetUrl": "https://accounts.invalid/reset/password",
  "primary-price-token": "market-price-feed-name",
  "CacheKey": "http-audit-log-cache-key-v1",
  "Formatter": "Serilog.Formatting.Compact.CompactJsonFormatter",
  "expression": "RequestPath not like '/health%' and StatusCode >= 500",
  "SensitiveHeaders": ["Authorization", "Password", "X-APISIX-KEY"],
  "EmptyPassword": "",
  "Nested": {
    "Password": "${DATABASE_PASSWORD}",
    "ClientSecret": "{{ secret_ref }}",
    "SecretToken": "%ELASTIC_APM_TOKEN%",
    "AccessToken": "vault://team/service/token",
    "RefreshToken": "@Microsoft.KeyVault(SecretUri=https://vault.invalid/secrets/token)",
    "SigningSecret": "APISIX_ADMIN_KEY",
    "WebhookSecret": "0000000000000000",
    "ConsumerSecret": "change_me"
  }
}`)

	findings := (&StructuredConfigDetector{}).Scan(context.Background(), data)
	assert.Empty(t, findings)
}

func TestStructuredConfigDetector_JSONCCommentsTrailingCommaAndRecovery(t *testing.T) {
	data := []byte(`{
  // "Password": "comment-only-secret-9mN2pQ7r"
  "BrokenScalar": true
  "Nested": {
    /* "ClientSecret": "block-comment-secret-9mN2pQ7r" */
    "ClientSecret": "actual-fixture-secret-9mN2pQ7r",
  },
}`)

	findings := (&StructuredConfigDetector{}).Scan(context.Background(), data)
	require.Len(t, findings, 1, "missing comma recovery must not hide a later valid key/value pair")
	assert.Equal(t, "Nested.ClientSecret", findings[0].ExtraData["key_path"])
}

func TestStructuredConfigDetector_EscapedKeyAndExactSourceSpan(t *testing.T) {
	data := []byte(`{"Pass\u0077ord":"ab\\cd-9mN2pQ7r"}`)
	findings := (&StructuredConfigDetector{}).Scan(context.Background(), data)
	require.Len(t, findings, 1)
	assert.Equal(t, "Password", findings[0].ExtraData["key_name"])
	assert.Equal(t, `ab\\cd-9mN2pQ7r`, string(findings[0].Raw), "Raw must be the exact source representation, not a whole line")
	assert.Equal(t, string(findings[0].Raw), string(data[findings[0].ByteStart:findings[0].ByteEnd]))
}

func TestStructuredConfigDetector_KeyNormalization(t *testing.T) {
	tests := map[string]string{
		"ClientSecret":   "clientsecret",
		"client_secret":  "clientsecret",
		"client-secret":  "clientsecret",
		"CLIENT_SECRET":  "clientsecret",
		"SecretToken":    "secrettoken",
		"signing.secret": "signingsecret",
		"price-token":    "pricetoken",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, canonicalConfigKey(input))
		})
	}
}

func TestStructuredConfigDetector_SupportedSecretRoles(t *testing.T) {
	keys := []string{
		"Password", "Passwd", "Passphrase", "Secret", "ClientSecret",
		"SecretToken", "AccessToken", "RefreshToken", "AuthToken", "BearerToken",
		"SigningSecret", "WebhookSecret", "ConsumerSecret", "AppSecret",
		"ApplicationSecret", "MasterSecret", "MasterKey", "EncryptionKey", "PrivateKey",
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:%q", key, fmt.Sprintf("fixture-%02d-9mN2pQ7rT4vW8xY", i))
	}
	b.WriteByte('}')

	findings := (&StructuredConfigDetector{}).Scan(context.Background(), []byte(b.String()))
	require.Len(t, findings, len(keys))
	for i, got := range findings {
		assert.Equal(t, keys[i], got.ExtraData["key_name"])
	}
}

func TestStructuredConfigDetector_ResourceBounds(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		data := []byte(strings.Repeat(`{"nested":`, maxStructuredDepth+2) +
			`{"Password":"fixture-secret-9mN2pQ7r"}` + strings.Repeat("}", maxStructuredDepth+3))
		assert.Empty(t, (&StructuredConfigDetector{}).Scan(context.Background(), data))
	})

	t.Run("finding cap", func(t *testing.T) {
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < maxStructuredFindings+20; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "%q:%q", "Password", fmt.Sprintf("fixture-%04d-9mN2pQ7r", i))
		}
		b.WriteByte('}')
		assert.Len(t, (&StructuredConfigDetector{}).Scan(context.Background(), []byte(b.String())), maxStructuredFindings)
	})
}

func TestStructuredConfigDetector_MalformedAndNonJSONInputsDoNotPanic(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		[]byte(`{"Password":"unterminated`),
		[]byte(`{"Password":"bad\qescape"}`),
		[]byte(`/* unterminated comment`),
		[]byte(`Password=fixture-secret-9mN2pQ7r`),
	}
	for _, input := range inputs {
		assert.NotPanics(t, func() {
			_ = (&StructuredConfigDetector{}).Scan(context.Background(), input)
		})
	}
}

func TestStructuredConfigDetector_DeterministicSourceOrder(t *testing.T) {
	data := []byte(`{"Z":{"Password":"fixture-z-9mN2pQ7r"},"A":{"ClientSecret":"fixture-a-9mN2pQ7r"}}`)
	findings := (&StructuredConfigDetector{}).Scan(context.Background(), data)
	require.Len(t, findings, 2)
	paths := []string{findings[0].ExtraData["key_path"], findings[1].ExtraData["key_path"]}
	assert.Equal(t, []string{"Z.Password", "A.ClientSecret"}, paths)
	assert.True(t, sort.IntsAreSorted([]int{findings[0].ByteStart, findings[1].ByteStart}))
}

func FuzzStructuredConfigDetector(f *testing.F) {
	f.Add([]byte(`{"Password":"fixture-secret-9mN2pQ7r"}`))
	f.Add([]byte(`{"SensitiveHeaders":["Password"]}`))
	f.Add([]byte(`{"Password":"${PASSWORD}"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		findings := (&StructuredConfigDetector{}).Scan(context.Background(), data)
		for _, got := range findings {
			require.GreaterOrEqual(t, got.ByteStart, 0)
			require.Greater(t, got.ByteEnd, got.ByteStart)
			require.LessOrEqual(t, got.ByteEnd, len(data))
			require.Equal(t, string(got.Raw), string(data[got.ByteStart:got.ByteEnd]))
		}
	})
}

func BenchmarkStructuredConfigDetector_Appsettings(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("testdata", "appsettings.synthetic.json"))
	if err != nil {
		b.Fatal(err)
	}
	d := &StructuredConfigDetector{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = d.Scan(context.Background(), data)
	}
}

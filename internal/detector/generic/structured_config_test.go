package generic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/dbconn"
	"github.com/HodeTech/leakwatch/internal/detector/shopify"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructuredConfigDetector_Metadata(t *testing.T) {
	d := &StructuredConfigDetector{}
	assert.Equal(t, "structured-config-secret", d.ID())
	assert.Equal(t, "Structured Configuration Secret", d.Description())
	assert.Empty(t, d.Keywords(), "escaped JSON keys require an always-run bounded parser")
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
    "ConsumerSecret": "change_me",
    "Password": "string",
    "Passphrase": "redacted",
    "AuthToken": "$AUTH_TOKEN",
    "AuthToken": "$auth_token",
    "BearerToken": "$(BEARER_TOKEN)",
    "AppSecret": "<secret>",
    "ClientSecret": "/run/secrets/client-secret",
    "Password": "file:///run/secrets/db-password",
    "PrivateKey": "/etc/ssl/private/key.pem",
    "PrivateKey": "certs/private-key.pem",
    "PrivateKey": "C:\\certs\\private-key.pem",
    "PrivateKey": "\\\\server\\share\\private-key.pem",
    "MasterKey": "pkcs11:token=application;object=master-key",
    "EncryptionKey": "arn:aws:kms:eu-west-1:123456789012:key/example",
    "ApplicationSecret": "op://engineering/service/credential"
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

func TestStructuredConfigDetector_StrictJSONEscapes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "escaped slash", data: []byte(`{"Password":"ab\/cd-secret"}`)},
		{name: "BMP unicode", data: []byte(`{"Password":"secret-\u00e7"}`)},
		{name: "surrogate pair", data: []byte(`{"Password":"secret-\uD83D\uDE00"}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := (&StructuredConfigDetector{}).Scan(context.Background(), tc.data)
			require.Len(t, findings, 1)
			assert.Equal(t, string(findings[0].Raw), string(tc.data[findings[0].ByteStart:findings[0].ByteEnd]))
		})
	}

	invalid := [][]byte{
		[]byte(`{"Password":"secret-\x41"}`),
		[]byte(`{"Password":"secret-\a"}`),
		[]byte(`{"Password":"secret-\uD83D"}`),
		[]byte(`{"Password":"secret-\uDE00"}`),
		[]byte(`{"Password":"secret-\uD83D\u0041"}`),
	}
	for _, data := range invalid {
		assert.Empty(t, (&StructuredConfigDetector{}).Scan(context.Background(), data))
	}
}

func TestStructuredConfigDetector_SlashBearingSecretIsNotMistakenForPath(t *testing.T) {
	data := []byte(`{"ClientSecret":"abc/def+ghi=9mN2"}`)
	require.Len(t, (&StructuredConfigDetector{}).Scan(context.Background(), data), 1)
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

func TestStructuredConfigDetector_EverySupportedRoleMatchesThroughMatcher(t *testing.T) {
	keys := []string{
		"Password", "Passwd", "Passphrase", "Secret", "ClientSecret",
		"SecretToken", "AccessToken", "RefreshToken", "AuthToken", "BearerToken",
		"SigningSecret", "WebhookSecret", "ConsumerSecret", "AppSecret",
		"ApplicationSecret", "MasterSecret", "MasterKey", "EncryptionKey", "PrivateKey",
	}
	d := &StructuredConfigDetector{}
	for i, key := range keys {
		t.Run(key, func(t *testing.T) {
			data := []byte(fmt.Sprintf("{%q:%q}", key, fmt.Sprintf("fixture-%02d-9mN2pQ7rT4vW8xY", i)))
			assert.Equal(t, d.Scan(context.Background(), data), testutil.ScanViaMatcher(d, data))
			require.Len(t, testutil.ScanViaMatcher(d, data), 1)
		})
	}

	escaped := []byte(`{"Pass\u0077ord":"fixture-escaped-9mN2pQ7r"}`)
	assert.Equal(t, d.Scan(context.Background(), escaped), testutil.ScanViaMatcher(d, escaped))
	require.Len(t, testutil.ScanViaMatcher(d, escaped), 1)
}

func TestStructuredConfigDetector_ProviderOverlapPrefersSpecializedFinding(t *testing.T) {
	data := []byte(`{"AccessToken":"shpat_0123456789abcdef0123456789abcdef"}`)
	eng := engine.New(engine.Config{
		Concurrency: 1,
		Detectors: []detector.Detector{
			&StructuredConfigDetector{},
			&shopify.Detector{},
		},
	})

	result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "shopify-access-token", result.Findings[0].DetectorID)
}

func TestStructuredConfigDetector_ResourceBounds(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		data := []byte(strings.Repeat(`{"nested":`, maxStructuredDepth+2) +
			`{"Password":"fixture-secret-9mN2pQ7r"}` + strings.Repeat("}", maxStructuredDepth+3))
		assert.Empty(t, (&StructuredConfigDetector{}).Scan(context.Background(), data))
	})

	t.Run("deep non-empty array terminates", func(t *testing.T) {
		data := []byte(`{"Deep":` + strings.Repeat("[", maxStructuredDepth+2) +
			`"ordinary-value"` + strings.Repeat("]", maxStructuredDepth+2) +
			`,"Password":"shallow-fixture-secret-9mN2pQ7r"}`)
		done := make(chan []detector.RawFinding, 1)
		go func() {
			done <- (&StructuredConfigDetector{}).Scan(context.Background(), data)
		}()
		select {
		case findings := <-done:
			require.Len(t, findings, 1)
			assert.Equal(t, "Password", findings[0].ExtraData["key_name"])
		case <-time.After(time.Second):
			t.Fatal("deep array scan did not terminate")
		}
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

func TestStructuredConfigDetector_TokenRetentionCapCannotHideTrailingSecret(t *testing.T) {
	var b strings.Builder
	b.Grow(maxStructuredTokens + 128)
	b.WriteByte('[')
	for i := 0; i < maxStructuredTokens/2+10; i++ {
		b.WriteString("0,")
	}
	b.WriteString(`{"Password":"trailing-fixture-secret-9mN2pQ7r"}]`)

	findings := (&StructuredConfigDetector{}).Scan(context.Background(), []byte(b.String()))
	require.Len(t, findings, 1)
	assert.Equal(t, "Password", findings[0].ExtraData["key_name"])
	assert.Equal(t, "Password", findings[0].ExtraData["key_path"], "path safely falls back after retention cap")
}

func TestStructuredConfigDetector_CancelledContextReturnsNoPartialResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := []byte(`{"Password":"fixture-secret-9mN2pQ7r"}`)
	assert.Empty(t, (&StructuredConfigDetector{}).Scan(ctx, data))
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

func TestStructuredConfigDetector_LexerAndReferenceBoundaries(t *testing.T) {
	t.Run("string bounds", func(t *testing.T) {
		_, next, ok, complete := scanJSONString(context.Background(), []byte(`"trailing\`), 0, 0)
		assert.False(t, ok)
		assert.True(t, complete)
		assert.Equal(t, len(`"trailing\`), next)

		overlong := []byte(`"` + strings.Repeat("a", maxStructuredStringLen+1) + `"`)
		_, next, ok, complete = scanJSONString(context.Background(), overlong, 0, 0)
		assert.False(t, ok)
		assert.True(t, complete)
		assert.Equal(t, len(overlong), next)
	})

	t.Run("path parser boundaries", func(t *testing.T) {
		p := &jsonPathParser{}
		p.parseValue(nil, 0)
		assert.Zero(t, p.pos)

		paths := buildJSONPaths([]jsonToken{
			{kind: jsonObjectStart},
			{kind: jsonString, text: "missing-colon"},
			{kind: jsonOther},
			{kind: jsonObjectEnd},
		})
		assert.Empty(t, paths)
	})

	t.Run("template syntax", func(t *testing.T) {
		assert.False(t, isDollarReference(""))
		assert.False(t, isDollarReference("$"))
		assert.False(t, isDollarReference("$NOT-A-REFERENCE"))
		assert.True(t, isDollarReference("$lower_case_1"))
		assert.False(t, isAngleReference("<>"))
		assert.False(t, isAngleReference("<not/a/reference>"))
		assert.True(t, isAngleReference("<client secret>"))
	})

	t.Run("value length", func(t *testing.T) {
		assert.False(t, isContextSecretValue("Password", "abc"))
		assert.False(t, isContextSecretValue("Password", strings.Repeat("x", maxStructuredStringLen+1)))
		assert.True(t, isContextSecretValue("Password", "s3cure"))
	})
}

type pollCancelContext struct {
	done   chan struct{}
	polls  int
	closed bool
}

func newPollCancelContext() *pollCancelContext {
	return &pollCancelContext{done: make(chan struct{})}
}

func (c *pollCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *pollCancelContext) Done() <-chan struct{} {
	c.poll()
	return c.done
}

func (c *pollCancelContext) Err() error {
	c.poll()
	if c.closed {
		return context.Canceled
	}
	return nil
}

func (c *pollCancelContext) Value(any) any { return nil }

func (c *pollCancelContext) poll() {
	c.polls++
	if c.polls >= 2 && !c.closed {
		close(c.done)
		c.closed = true
	}
}

func TestStructuredConfigDetector_LongTokenLoopsHonorCancellation(t *testing.T) {
	inputs := map[string][]byte{
		"string":        []byte(`"` + strings.Repeat("a", 1<<20)),
		"line comment":  []byte(`//` + strings.Repeat("a", 1<<20)),
		"block comment": []byte(`/*` + strings.Repeat("a", 1<<20)),
		"bare scalar":   []byte(strings.Repeat("a", 1<<20)),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			_, _, complete := lexJSONLike(newPollCancelContext(), data)
			assert.False(t, complete)
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
	f.Add([]byte(`{"Password":"ab\/cd-secret"}`))
	f.Add([]byte(`{"Password":"secret-\uD83D\uDE00"}`))
	f.Add([]byte(strings.Repeat("[", maxStructuredDepth+2) + `"Password"` + strings.Repeat("]", maxStructuredDepth+2)))
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

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
	twiliodetector "github.com/HodeTech/leakwatch/internal/detector/twilio"
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

func TestStructuredConfigDetector_AllSupportedFormats_MatcherAndEngineParity(t *testing.T) {
	secret := "fixture-secret-9mN2pQ7rT4vW8xY"
	tests := []struct {
		name       string
		format     string
		path       string
		data       []byte
		valueStart string
	}{
		{
			name: "nested JSON", format: "json", path: "Service.Credentials.ClientSecret",
			data:       []byte(`{"Service":{"Credentials":{"ClientSecret":"` + secret + `"}}}`),
			valueStart: secret,
		},
		{
			name: "nested YAML", format: "yaml", path: "service.credentials.client_secret",
			data:       []byte("service:\n  credentials:\n    client_secret: \"" + secret + "\"\n"),
			valueStart: secret,
		},
		{
			name: "flat YAML document", format: "yaml", path: "password",
			data:       []byte("service: fixture\npassword: " + secret + "\n"),
			valueStart: secret,
		},
		{
			name: "YAML literal block", format: "yaml", path: "password",
			data:       []byte("---\npassword: |\n  " + secret + "\n"),
			valueStart: secret,
		},
		{
			name: "YAML escaped single quote", format: "yaml", path: "service.client_secret",
			data:       []byte("service:\n  client_secret: 'fixture-it''s-secret-9mN2pQ7r'\n"),
			valueStart: "fixture-it''s-secret-9mN2pQ7r",
		},
		{
			name: "nested TOML", format: "toml", path: "service.credentials.client_secret",
			data:       []byte("[service.credentials]\nclient_secret = \"" + secret + "\"\n"),
			valueStart: secret,
		},
		{
			name: "TOML unicode escape", format: "toml", path: "service.client_secret",
			data:       []byte("[service]\nclient_secret = \"fixture\\u002Dsecret-9mN2pQ7r\"\n"),
			valueStart: `fixture\u002Dsecret-9mN2pQ7r`,
		},
		{
			name: "TOML dotted key", format: "toml", path: "service.password",
			data:       []byte("service.password = \"" + secret + "\"\nother = \"fixture\"\n"),
			valueStart: secret,
		},
		{
			name: "sectionless TOML", format: "toml", path: "client_secret",
			data:       []byte("service_name = \"fixture\"\nclient_secret = \"" + secret + "\"\n"),
			valueStart: secret,
		},
		{
			name: "nested XML", format: "xml", path: "configuration.service.credentials.ClientSecret",
			data:       []byte("<configuration><service><credentials><ClientSecret>" + secret + "</ClientSecret></credentials></service></configuration>"),
			valueStart: secret,
		},
		{
			name: "XML CDATA", format: "xml", path: "configuration.Password",
			data:       []byte("<configuration><Password><![CDATA[" + secret + "]]></Password></configuration>"),
			valueStart: secret,
		},
		{
			name: "dotenv", format: "dotenv", path: "CLIENT_SECRET",
			data:       []byte("SERVICE_NAME=fixture\nCLIENT_SECRET=" + secret + "\n"),
			valueStart: secret,
		},
		{
			name: "YAML sequence mapping", format: "yaml", path: "users.password",
			data:       []byte("users:\n  - password: " + secret + "\n"),
			valueStart: secret,
		},
		{
			name: "XML key value attributes", format: "xml", path: "configuration.add.Password",
			data:       []byte("<configuration><add key=\"Password\" value=\"" + secret + "\"/></configuration>"),
			valueStart: secret,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			det := &StructuredConfigDetector{}
			direct := det.Scan(t.Context(), tc.data)
			viaMatcher := testutil.ScanViaMatcher(det, tc.data)
			require.Equal(t, direct, viaMatcher)
			require.Len(t, direct, 1)
			assert.Equal(t, tc.format, direct[0].ExtraData["config_format"])
			assert.Equal(t, tc.path, direct[0].ExtraData["key_path"])
			assert.Equal(t, tc.valueStart, string(direct[0].Raw))
			assert.Equal(t, string(direct[0].Raw), string(tc.data[direct[0].ByteStart:direct[0].ByteEnd]))

			eng := engine.New(engine.Config{Concurrency: 1, Detectors: []detector.Detector{det}})
			result, err := eng.Scan(t.Context(), &fixtureSource{data: tc.data})
			require.NoError(t, err)
			require.Len(t, result.Findings, 1)
			assert.Equal(t, det.ID(), result.Findings[0].DetectorID)
			assert.Empty(t, result.Findings[0].Raw)
		})
	}
}

func TestStructuredConfigDetector_AllSupportedFormats_HardNegatives(t *testing.T) {
	tests := map[string][]byte{
		"json":   []byte(`{"Nested":{"Password":"${DATABASE_PASSWORD}","PasswordResetUrl":"https://accounts.invalid/reset/password","ClientId":"client-identifier-123456"}}`),
		"yaml":   []byte("nested:\n  password: ${DATABASE_PASSWORD}\n  password_reset_url: https://accounts.invalid/reset/password\n  client_id: client-identifier-123456\n"),
		"toml":   []byte("[nested]\npassword = \"${DATABASE_PASSWORD}\"\npassword_reset_url = \"https://accounts.invalid/reset/password\"\nclient_id = \"client-identifier-123456\"\n"),
		"xml":    []byte("<configuration><nested><Password>${DATABASE_PASSWORD}</Password><PasswordResetUrl>https://accounts.invalid/reset/password</PasswordResetUrl><ClientId>client-identifier-123456</ClientId></nested></configuration>"),
		"dotenv": []byte("PASSWORD=${DATABASE_PASSWORD}\nPASSWORD_RESET_URL=https://accounts.invalid/reset/password\nCLIENT_ID=client-identifier-123456\n"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, (&StructuredConfigDetector{}).Scan(t.Context(), data))
		})
	}
}

func TestStructuredConfigDetector_YAMLAliasIsReferenceNotSecret(t *testing.T) {
	data := []byte("---\nvalue: &db_password fixture-secret-9mN2pQ7r\npassword: *db_password\n")
	assert.Empty(t, (&StructuredConfigDetector{}).Scan(t.Context(), data))
}

func TestStructuredConfigDetector_FormatAdapterBoundaries(t *testing.T) {
	t.Run("XML entity preserves exact source span", func(t *testing.T) {
		data := []byte(`<configuration><Password>fixture&amp;secret-9mN2pQ7r</Password></configuration>`)
		findings := (&StructuredConfigDetector{}).Scan(t.Context(), data)
		require.Len(t, findings, 1)
		assert.Equal(t, `fixture&amp;secret-9mN2pQ7r`, string(findings[0].Raw))
		assert.Equal(t, string(findings[0].Raw), string(data[findings[0].ByteStart:findings[0].ByteEnd]))
	})

	t.Run("UTF-8 BOM preserves original byte span", func(t *testing.T) {
		for _, data := range [][]byte{
			append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"Password":"fixture-bom-secret-9mN2pQ7r"}`)...),
			append([]byte{0xef, 0xbb, 0xbf}, []byte(`<Password>fixture-bom-secret-9mN2pQ7r</Password>`)...),
		} {
			findings := (&StructuredConfigDetector{}).Scan(t.Context(), data)
			require.Len(t, findings, 1)
			assert.Equal(t, "fixture-bom-secret-9mN2pQ7r", string(findings[0].Raw))
			assert.Equal(t, string(findings[0].Raw), string(data[findings[0].ByteStart:findings[0].ByteEnd]))
		}
	})

	t.Run("JSON top-level array is not TOML", func(t *testing.T) {
		data := []byte(`[{"Password":"fixture-array-secret-9mN2pQ7r"}]`)
		findings := (&StructuredConfigDetector{}).Scan(t.Context(), data)
		require.Len(t, findings, 1)
		assert.Equal(t, "json", findings[0].ExtraData["config_format"])
		assert.Equal(t, "[0].Password", findings[0].ExtraData["key_path"])
	})

	t.Run("CRLF and inline comments keep exact value span", func(t *testing.T) {
		data := []byte("service:\r\n  password: fixture-crlf-secret-9mN2pQ7r # explanation\r\n")
		findings := (&StructuredConfigDetector{}).Scan(t.Context(), data)
		require.Len(t, findings, 1)
		assert.Equal(t, "fixture-crlf-secret-9mN2pQ7r", string(findings[0].Raw))
		assert.Equal(t, "service.password", findings[0].ExtraData["key_path"])
	})

	t.Run("malformed XML returns no partial findings", func(t *testing.T) {
		data := []byte(`<configuration><Password>fixture-secret-9mN2pQ7r</Password><broken></configuration>`)
		assert.Empty(t, (&StructuredConfigDetector{}).Scan(t.Context(), data))
	})

	t.Run("large accepted line input is scanned and cancellation is prompt", func(t *testing.T) {
		line := append([]byte("PASSWORD=fixture-secret-9mN2pQ7r\n#"), []byte(strings.Repeat("x", 4*1024*1024))...)
		findings := (&StructuredConfigDetector{}).Scan(t.Context(), line)
		require.Len(t, findings, 1)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		started := time.Now()
		assert.Empty(t, (&StructuredConfigDetector{}).Scan(ctx, line))
		assert.Less(t, time.Since(started), 250*time.Millisecond)
	})

	t.Run("source code assignments are not configuration", func(t *testing.T) {
		inputs := [][]byte{
			[]byte("password := request.Password\nif password == \"\" { return err }\n"),
			[]byte("Password = GetPasswordFromRequest();\nreturn Password;\n"),
			[]byte("const PASSWORD = process.env.PASSWORD;\nconsole.log('configured');\n"),
			[]byte("PASSWORD=os.getenv(\"PASSWORD\")\n"),
		}
		for _, input := range inputs {
			assert.Empty(t, (&StructuredConfigDetector{}).Scan(t.Context(), input), string(input))
		}
	})
}

func TestStructuredConfigDetector_DynamicPathMetadataIsBoundedAndSafe(t *testing.T) {
	secretParent := "sk-" + strings.Repeat("Ab7x", 40)
	value := "fixture-value-secret-9mN2pQ7r"
	data := []byte(fmt.Sprintf(`{%q:{"Password":%q}}`, secretParent, value))
	findings := (&StructuredConfigDetector{}).Scan(t.Context(), data)
	require.Len(t, findings, 1)
	assert.Equal(t, "<dynamic-key>.Password", findings[0].ExtraData["key_path"])
	assert.NotContains(t, findings[0].ExtraData["key_path"], secretParent)
	assert.NotContains(t, findings[0].ExtraData["key_path"], value)

	controlParent := "line\nbreak"
	data = []byte(fmt.Sprintf(`{%q:{"Password":%q}}`, controlParent, value))
	findings = (&StructuredConfigDetector{}).Scan(t.Context(), data)
	require.Len(t, findings, 1)
	assert.Equal(t, "<dynamic-key>.Password", findings[0].ExtraData["key_path"])
	assert.NotContains(t, findings[0].ExtraData["key_path"], "\n")
}

func TestStructuredConfigDetector_LineSyntaxEdges(t *testing.T) {
	t.Run("format confidence", func(t *testing.T) {
		format, ok := detectLineConfigFormat(t.Context(), []byte("# comment\nexport CLIENT_SECRET=fixture-secret-9mN2pQ7r\n"))
		assert.True(t, ok)
		assert.Equal(t, formatDotenv, format)

		format, ok = detectLineConfigFormat(t.Context(), []byte("---\npassword: fixture-secret-9mN2pQ7r\n"))
		assert.True(t, ok)
		assert.Equal(t, formatYAML, format)

		for _, data := range [][]byte{
			{},
			[]byte("# comment only\n"), []byte("password=value\n"),
			[]byte("CLIENT-SECRET=value\n"), []byte("CLIENT_SECRET=\n"),
			[]byte("CLIENT_SECRET=value\nnot config\n"),
		} {
			_, confident := detectLineConfigFormat(t.Context(), data)
			assert.False(t, confident, string(data))
		}
	})

	t.Run("assignment and scalar rejection", func(t *testing.T) {
		for _, line := range [][]byte{
			{},
			[]byte("# comment"), []byte("; comment"), []byte("// comment"),
			[]byte("missing delimiter"), []byte("bad key!=value"),
		} {
			_, ok := parseLineAssignment(line, 0, formatDotenv)
			assert.False(t, ok, string(line))
		}

		parent, ok := parseLineAssignment([]byte("\tcredentials:"), 0, formatYAML)
		assert.True(t, ok)
		assert.False(t, parent.hasValue)
		assert.Equal(t, 8, parent.indent)

		exportLine := []byte("export   CLIENT_SECRET='fixture-secret-9mN2pQ7r'")
		exported, ok := parseLineAssignment(exportLine, 10, formatDotenv)
		assert.True(t, ok)
		assert.Equal(t, "fixture-secret-9mN2pQ7r", exported.value)
		assert.Equal(t, exported.value, string(exportLine[exported.valueStart-10:exported.valueEnd-10]))

		for _, value := range [][]byte{
			{},
			[]byte(" "), []byte("|"), []byte("> folded"), []byte("[array]"), []byte("{object}"),
			[]byte("\"unterminated"), []byte("\"valid\" trailing"), []byte("\"bad\\q\""),
		} {
			_, _, _, scalarOK := parseLineScalar(value, 0, formatYAML)
			assert.False(t, scalarOK, string(value))
		}
		_, _, _, scalarOK := parseLineScalar([]byte("bare-toml-value"), 0, formatTOML)
		assert.False(t, scalarOK)
		decoded, start, end, scalarOK := parseLineScalar([]byte("  \"fixture\\nsecret\" # note"), 20, formatTOML)
		assert.True(t, scalarOK)
		assert.Equal(t, "fixture\nsecret", decoded)
		assert.Equal(t, 23, start)
		assert.Greater(t, end, start)
		decoded, _, _, scalarOK = parseLineScalar([]byte(`'fixture-it''s-secret-9mN2pQ7r'`), 0, formatYAML)
		assert.True(t, scalarOK)
		assert.Equal(t, "fixture-it's-secret-9mN2pQ7r", decoded)
		decoded, _, _, scalarOK = parseLineScalar([]byte(`"fixture\Nsecret-9mN2pQ7r"`), 0, formatYAML)
		assert.True(t, scalarOK)
		assert.Equal(t, "fixture\u0085secret-9mN2pQ7r", decoded)
		decoded, _, _, scalarOK = parseLineScalar([]byte(`"fixture\u002Dsecret-9mN2pQ7r"`), 0, formatTOML)
		assert.True(t, scalarOK)
		assert.Equal(t, "fixture-secret-9mN2pQ7r", decoded)
		_, _, _, scalarOK = parseLineScalar([]byte(`"fixture\x2Dsecret-9mN2pQ7r"`), 0, formatTOML)
		assert.False(t, scalarOK, "Go-only escapes must not be accepted as TOML")
		_, _, _, scalarOK = parseLineScalar([]byte(`'fixture-it''s-secret-9mN2pQ7r'`), 0, formatTOML)
		assert.False(t, scalarOK, "YAML doubled-quote syntax must not be accepted as TOML")
	})

	t.Run("helper boundaries", func(t *testing.T) {
		assert.Equal(t, -1, findClosingQuote([]byte(`"escaped\"`), '"'))
		assert.Equal(t, 10, findClosingQuote([]byte(`"escaped\\"`), '"'))
		assert.False(t, isPlainConfigKey(nil))
		assert.False(t, isPlainConfigKey([]byte("bad key")))
		assert.True(t, isPlainConfigKey([]byte("service.credentials")))

		for _, section := range [][]byte{[]byte("[]"), []byte("[[array.table]]"), []byte("[bad section]"), []byte("plain")} {
			_, ok := parseTOMLSection(section)
			assert.False(t, ok, string(section))
		}
		parts, ok := parseTOMLSection([]byte("[ service.credentials ]"))
		assert.True(t, ok)
		assert.Equal(t, []string{"service", "credentials"}, parts)
		parts, ok = parseTOMLSection([]byte("[service.credentials] # provider settings"))
		assert.True(t, ok)
		assert.Equal(t, []string{"service", "credentials"}, parts)

		parts, ok = parseTOMLDottedKey([]byte(`"service".'credentials'.password`))
		assert.True(t, ok)
		assert.Equal(t, []string{"service", "credentials", "password"}, parts)
		for _, key := range [][]byte{
			nil, []byte("service..password"), []byte(`"".password`),
			[]byte(`"unterminated.password`), []byte("bad key.password"),
		} {
			_, ok := parseTOMLDottedKey(key)
			assert.False(t, ok, string(key))
		}

		for _, indicator := range [][]byte{
			[]byte("|"), []byte(">-"), []byte("|2 # comment"), []byte(">+4"),
		} {
			assert.True(t, isYAMLBlockIndicator(indicator), string(indicator))
		}
		for _, indicator := range [][]byte{
			nil, []byte("plain"), []byte("| trailing"), []byte(">!"),
		} {
			assert.False(t, isYAMLBlockIndicator(indicator), string(indicator))
		}

		assert.False(t, hasNestedYAMLSignals([]yamlSignal{{indent: 0, hasValue: true}}))
		assert.False(t, hasNestedYAMLSignals([]yamlSignal{{indent: 0}, {indent: 0, hasValue: true}}))
		assert.True(t, hasNestedYAMLSignals([]yamlSignal{{indent: 0}, {indent: 2, hasValue: true}}))
	})

	t.Run("YAML block scalar decoding and failure boundaries", func(t *testing.T) {
		literal := []byte("  first-secret-line\n  second-secret-line\nsibling: value\n")
		value, start, end, next, ok := parseYAMLBlockScalar(t.Context(), literal, 0, 0, '|')
		assert.True(t, ok)
		assert.Equal(t, "first-secret-line\nsecond-secret-line", value)
		assert.Equal(t, "first-secret-line\n  second-secret-line", string(literal[start:end]))
		assert.Equal(t, strings.Index(string(literal), "sibling:"), next)

		folded := []byte("  first-secret-line\n\n  second-secret-line\n")
		value, _, _, _, ok = parseYAMLBlockScalar(t.Context(), folded, 0, 0, '>')
		assert.True(t, ok)
		assert.Equal(t, "first-secret-line\nsecond-secret-line", value)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, _, _, _, ok = parseYAMLBlockScalar(ctx, literal, 0, 0, '|')
		assert.False(t, ok)
		for _, invalid := range [][]byte{
			[]byte("\tsecret\n"), []byte("secret\n"), []byte("  \n"),
		} {
			_, _, _, _, ok = parseYAMLBlockScalar(t.Context(), invalid, 0, 0, '|')
			assert.False(t, ok, string(invalid))
		}
	})

	t.Run("YAML sibling paths and cancellation", func(t *testing.T) {
		data := []byte("first:\n  password: fixture-first-secret-9mN2pQ7r\nsecond:\n  client_secret: fixture-second-secret-9mN2pQ7r\n")
		findings := (&StructuredConfigDetector{}).Scan(t.Context(), data)
		require.Len(t, findings, 2)
		assert.Equal(t, "first.password", findings[0].ExtraData["key_path"])
		assert.Equal(t, "second.client_secret", findings[1].ExtraData["key_path"])

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		assert.Empty(t, (&StructuredConfigDetector{}).Scan(ctx, []byte("CLIENT_SECRET=fixture-secret-9mN2pQ7r\n")))
		assert.Empty(t, (&StructuredConfigDetector{}).scanLineConfig(t.Context(), []byte{0xff, 0xfe}))
	})
}

func TestStructuredConfigDetector_XMLSyntaxEdges(t *testing.T) {
	det := &StructuredConfigDetector{}

	t.Run("whitespace source span", func(t *testing.T) {
		data := []byte("<?xml version=\"1.0\"?><configuration>outside<Password> \t\r\nfixture-secret-9mN2pQ7r \n</Password><EmptyPassword/></configuration>")
		findings := det.Scan(t.Context(), data)
		require.Len(t, findings, 1)
		assert.Equal(t, "fixture-secret-9mN2pQ7r", string(findings[0].Raw))
	})

	t.Run("comments and child elements invalidate scalar", func(t *testing.T) {
		inputs := [][]byte{
			[]byte(`<configuration><Password><!-- generated -->fixture-secret-9mN2pQ7r</Password></configuration>`),
			[]byte(`<configuration><Password><value>fixture-secret-9mN2pQ7r</value></Password></configuration>`),
		}
		for _, input := range inputs {
			assert.Empty(t, det.Scan(t.Context(), input))
		}
	})

	t.Run("invalid input depth and cancellation fail closed", func(t *testing.T) {
		assert.Empty(t, det.scanXML(t.Context(), []byte{0xff, '<'}))
		deep := []byte(strings.Repeat("<n>", maxStructuredDepth+1) + strings.Repeat("</n>", maxStructuredDepth+1))
		assert.Empty(t, det.scanXML(t.Context(), deep))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		assert.Empty(t, det.scanXML(ctx, []byte(`<Password>fixture-secret-9mN2pQ7r</Password>`)))
	})
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

func TestStructuredConfigDetector_PairedTwilioSecretUsesProviderFindingOnly(t *testing.T) {
	keySID := "SK" + strings.Repeat("ab12cd34", 4)
	secret := strings.Repeat("Qw12Er34", 4)
	data := []byte(`{"Twilio":{"ApiKeySid":"` + keySID + `","ApiKeySecret":"` + secret + `"}}`)
	eng := engine.New(engine.Config{
		Concurrency: 2,
		Detectors: []detector.Detector{
			&StructuredConfigDetector{},
			&twiliodetector.Detector{},
		},
	})

	result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "twilio-api-key", result.Findings[0].DetectorID)
	assert.Empty(t, result.Findings[0].Raw)
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

func TestProviderDetectors_ExactSpansPreventRejectedDuplicateInlineIgnore(t *testing.T) {
	t.Run("Shopify", func(t *testing.T) {
		token := "shpat_0123456789abcdef0123456789abcdef"
		data := []byte("prefix_" + token + " # leakwatch:ignore:shopify-access-token\n" +
			"SHOPIFY_ACCESS_TOKEN=" + token + "\n")
		eng := engine.New(engine.Config{Concurrency: 1, Detectors: []detector.Detector{&shopify.Detector{}}})

		result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
		require.NoError(t, err)
		require.Len(t, result.Findings, 1)
		assert.Equal(t, 2, result.Findings[0].SourceMetadata.Line)
	})

	t.Run("Twilio", func(t *testing.T) {
		secret := strings.Repeat("Qw12Er34", 4)
		keySID := "SK" + strings.Repeat("ab12cd34", 4)
		data := []byte("NOTE=" + secret + " # leakwatch:ignore:twilio-api-key\n" +
			"TWILIO_API_KEY_SID=" + keySID + "\n" +
			"TWILIO_API_KEY_SECRET=" + secret + "\n")
		eng := engine.New(engine.Config{Concurrency: 1, Detectors: []detector.Detector{&twiliodetector.Detector{}}})

		result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
		require.NoError(t, err)
		require.Len(t, result.Findings, 1)
		assert.Equal(t, 3, result.Findings[0].SourceMetadata.Line)
	})

	t.Run("Twilio rejects template values and malformed SID context", func(t *testing.T) {
		keySID := "SK" + strings.Repeat("ab12cd34", 4)
		secret := strings.Repeat("Qw12Er34", 4)
		for _, data := range [][]byte{
			[]byte("TWILIO_API_KEY_SID=" + keySID + "\nTWILIO_API_KEY_SECRET=YOUR_TWILIO_API_KEY_SECRET\n"),
			[]byte("TWILIO_API_KEY_SID=" + keySID + "-suffix\nTWILIO_API_KEY_SECRET=" + secret + "\n"),
		} {
			eng := engine.New(engine.Config{Concurrency: 1, Detectors: []detector.Detector{&twiliodetector.Detector{}}})
			result, err := eng.Scan(context.Background(), &fixtureSource{data: data})
			require.NoError(t, err)
			assert.Empty(t, result.Findings)
		}
	})
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
	f.Add([]byte("service:\n  password: fixture-secret-9mN2pQ7r\n"))
	f.Add([]byte("[service]\npassword = \"fixture-secret-9mN2pQ7r\"\n"))
	f.Add([]byte(`<configuration><Password>fixture&amp;secret-9mN2pQ7r</Password></configuration>`))
	f.Add([]byte("PASSWORD=fixture-secret-9mN2pQ7r\n"))
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

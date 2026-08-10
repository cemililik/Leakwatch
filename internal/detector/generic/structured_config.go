package generic

import (
	"context"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	maxStructuredTokens    = 200_000
	maxStructuredDepth     = 64
	maxStructuredStringLen = 256 * 1024
	maxStructuredFindings  = 1_024
	minContextSecretLength = 4
)

// StructuredConfigDetector detects secrets stored in high-confidence leaf
// fields of JSON and JSON-with-comments configuration files. It uses a bounded
// lexer rather than scanning arbitrary high-entropy strings, so explicit field
// context can safely detect human-style and short secrets without weakening
// the generic detector's false-positive gates.
type StructuredConfigDetector struct{}

func (d *StructuredConfigDetector) ID() string          { return "structured-config-secret" }
func (d *StructuredConfigDetector) Description() string { return "Structured Configuration Secret" }
func (d *StructuredConfigDetector) Severity() finding.Severity {
	return finding.SeverityHigh
}

func (d *StructuredConfigDetector) Keywords() []string {
	return []string{
		"password", "passwd", "passphrase",
		"clientsecret", "client_secret", "client-secret",
		"secrettoken", "secret_token", "secret-token",
		"accesstoken", "access_token", "access-token",
		"refreshtoken", "refresh_token", "refresh-token",
		"signingsecret", "signing_secret", "signing-secret",
		"webhooksecret", "webhook_secret", "webhook-secret",
	}
}

func (d *StructuredConfigDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	tokens := lexJSONLike(data)
	if len(tokens) < 3 {
		return nil
	}

	paths := buildJSONPaths(tokens)
	findings := make([]detector.RawFinding, 0, 8)
	for i := 0; i+2 < len(tokens) && len(findings) < maxStructuredFindings; i++ {
		keyToken, colonToken, valueToken := tokens[i], tokens[i+1], tokens[i+2]
		if keyToken.kind != jsonString || colonToken.kind != jsonColon || valueToken.kind != jsonString {
			continue
		}
		if keyToken.depth > maxStructuredDepth || valueToken.depth > maxStructuredDepth {
			continue
		}
		if !isHighConfidenceSecretKey(keyToken.text) || isGenericOwnedSecretKey(keyToken.text) {
			continue
		}
		if !isContextSecretValue(valueToken.text) {
			continue
		}

		raw := data[valueToken.contentStart:valueToken.contentEnd]
		path := paths[valueToken.contentStart]
		if path == "" {
			path = keyToken.text
		}
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        raw,
			Redacted:   detector.RedactBytes(raw),
			ExtraData: map[string]string{
				"key_name":      keyToken.text,
				"key_path":      path,
				"config_format": "json",
			},
			ByteStart: valueToken.contentStart,
			ByteEnd:   valueToken.contentEnd,
		})
	}
	return findings
}

type jsonTokenKind uint8

const (
	jsonOther jsonTokenKind = iota
	jsonString
	jsonColon
	jsonComma
	jsonObjectStart
	jsonObjectEnd
	jsonArrayStart
	jsonArrayEnd
)

type jsonToken struct {
	kind                     jsonTokenKind
	start, end               int
	contentStart, contentEnd int
	depth                    int
	text                     string
}

// lexJSONLike tokenizes only the JSON structure needed for key/value
// extraction. It preserves byte offsets, skips // and /* */ comments, accepts
// trailing commas at the parser layer, and stops at explicit resource bounds.
func lexJSONLike(data []byte) []jsonToken {
	tokens := make([]jsonToken, 0, minInt(len(data)/8, 4_096))
	depth := 0
	for i := 0; i < len(data) && len(tokens) < maxStructuredTokens; {
		switch data[i] {
		case ' ', '\t', '\r', '\n':
			i++
		case '/':
			if i+1 < len(data) && data[i+1] == '/' {
				i += 2
				for i < len(data) && data[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < len(data) && data[i+1] == '*' {
				i += 2
				for i+1 < len(data) && (data[i] != '*' || data[i+1] != '/') {
					i++
				}
				if i+1 < len(data) {
					i += 2
				}
				continue
			}
			tokens = append(tokens, jsonToken{kind: jsonOther, start: i, end: i + 1, depth: depth})
			i++
		case '"':
			token, next, ok := scanJSONString(data, i, depth)
			i = next
			if ok {
				tokens = append(tokens, token)
			}
		case ':':
			tokens = append(tokens, jsonToken{kind: jsonColon, start: i, end: i + 1, depth: depth})
			i++
		case ',':
			tokens = append(tokens, jsonToken{kind: jsonComma, start: i, end: i + 1, depth: depth})
			i++
		case '{':
			tokens = append(tokens, jsonToken{kind: jsonObjectStart, start: i, end: i + 1, depth: depth})
			depth++
			i++
		case '[':
			tokens = append(tokens, jsonToken{kind: jsonArrayStart, start: i, end: i + 1, depth: depth})
			depth++
			i++
		case '}':
			if depth > 0 {
				depth--
			}
			tokens = append(tokens, jsonToken{kind: jsonObjectEnd, start: i, end: i + 1, depth: depth})
			i++
		case ']':
			if depth > 0 {
				depth--
			}
			tokens = append(tokens, jsonToken{kind: jsonArrayEnd, start: i, end: i + 1, depth: depth})
			i++
		default:
			start := i
			for i < len(data) && !isJSONDelimiter(data[i]) {
				i++
			}
			if i == start {
				i++
			}
			tokens = append(tokens, jsonToken{kind: jsonOther, start: start, end: i, depth: depth})
		}
	}
	return tokens
}

func scanJSONString(data []byte, start, depth int) (jsonToken, int, bool) {
	i := start + 1
	for i < len(data) {
		switch data[i] {
		case '\\':
			if i+1 >= len(data) {
				return jsonToken{}, len(data), false
			}
			i += 2
		case '"':
			end := i + 1
			if i-start-1 > maxStructuredStringLen {
				return jsonToken{}, end, false
			}
			decoded, err := strconv.Unquote(string(data[start:end]))
			if err != nil || !utf8.ValidString(decoded) {
				return jsonToken{}, end, false
			}
			return jsonToken{
				kind:         jsonString,
				start:        start,
				end:          end,
				contentStart: start + 1,
				contentEnd:   i,
				depth:        depth,
				text:         decoded,
			}, end, true
		default:
			i++
		}
	}
	return jsonToken{}, len(data), false
}

func isJSONDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '/', '"', ':', ',', '{', '}', '[', ']':
		return true
	default:
		return false
	}
}

type jsonPathParser struct {
	tokens []jsonToken
	pos    int
	paths  map[int]string
}

func buildJSONPaths(tokens []jsonToken) map[int]string {
	p := &jsonPathParser{tokens: tokens, paths: make(map[int]string)}
	for p.pos < len(tokens) {
		before := p.pos
		p.parseValue(nil, 0)
		if p.pos == before {
			p.pos++
		}
	}
	return p.paths
}

func (p *jsonPathParser) parseValue(path []string, depth int) {
	if p.pos >= len(p.tokens) || depth > maxStructuredDepth {
		return
	}
	switch p.tokens[p.pos].kind {
	case jsonObjectStart:
		p.parseObject(path, depth+1)
	case jsonArrayStart:
		p.parseArray(path, depth+1)
	case jsonString:
		p.paths[p.tokens[p.pos].contentStart] = joinJSONPath(path)
		p.pos++
	default:
		p.pos++
	}
}

func (p *jsonPathParser) parseObject(path []string, depth int) {
	p.pos++
	for p.pos < len(p.tokens) {
		if p.tokens[p.pos].kind == jsonObjectEnd {
			p.pos++
			return
		}
		if p.tokens[p.pos].kind == jsonComma {
			p.pos++
			continue
		}
		if p.tokens[p.pos].kind != jsonString {
			p.pos++
			continue
		}

		key := p.tokens[p.pos].text
		p.pos++
		if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != jsonColon {
			continue
		}
		p.pos++
		childPath := appendJSONPath(path, key)
		p.parseValue(childPath, depth)
	}
}

func (p *jsonPathParser) parseArray(path []string, depth int) {
	p.pos++
	index := 0
	for p.pos < len(p.tokens) {
		if p.tokens[p.pos].kind == jsonArrayEnd {
			p.pos++
			return
		}
		if p.tokens[p.pos].kind == jsonComma {
			p.pos++
			continue
		}
		p.parseValue(appendJSONPath(path, "["+strconv.Itoa(index)+"]"), depth)
		index++
	}
}

func appendJSONPath(path []string, component string) []string {
	out := make([]string, len(path), len(path)+1)
	copy(out, path)
	return append(out, component)
}

func joinJSONPath(path []string) string {
	var b strings.Builder
	for i, component := range path {
		if strings.HasPrefix(component, "[") {
			b.WriteString(component)
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(component)
	}
	return b.String()
}

func isHighConfidenceSecretKey(key string) bool {
	switch canonicalConfigKey(key) {
	case "password", "passwd", "passphrase", "secret",
		"clientsecret", "secrettoken", "accesstoken", "refreshtoken",
		"authtoken", "bearertoken", "signingsecret", "webhooksecret",
		"consumersecret", "appsecret", "applicationsecret", "mastersecret",
		"masterkey", "encryptionkey", "privatekey":
		return true
	default:
		return false
	}
}

// Generic API-key assignments and connection strings retain their existing
// specialized ownership. The structured detector must not double-report them.
func isGenericOwnedSecretKey(key string) bool {
	switch canonicalConfigKey(key) {
	case "apikey", "apisecret", "secretkey", "xapikey", "xapisixkey", "apisixkey", "apisixadminkey":
		return true
	default:
		return false
	}
}

func canonicalConfigKey(key string) string {
	parts := splitConfigIdentifier(key)
	return strings.Join(parts, "")
}

func splitConfigIdentifier(value string) []string {
	runes := []rune(value)
	parts := make([]string, 0, 4)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			parts = append(parts, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}

	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := runes[i-1]
		nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
		if unicode.IsUpper(r) && (unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower)) {
			flush(i)
			start = i
		}
	}
	flush(len(runes))
	return parts
}

func isContextSecretValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < minContextSecretLength || len(trimmed) > maxStructuredStringLen {
		return false
	}
	lower := strings.ToLower(trimmed)
	switch lower {
	case "password", "secret", "changeme", "change-me", "change_me", "dummy",
		"example", "notset", "not-set", "none", "null", "default", "test", "dev", "local":
		return false
	}
	if isPlaceholder([]byte(trimmed)) || isDegenerateValue([]byte(trimmed)) || isBareReference([]byte(trimmed)) {
		return false
	}
	if isExternalSecretReference(lower, trimmed) {
		return false
	}
	return true
}

func isExternalSecretReference(lower, original string) bool {
	if (strings.HasPrefix(original, "${") && strings.HasSuffix(original, "}")) ||
		(strings.HasPrefix(original, "{{") && strings.HasSuffix(original, "}}")) ||
		(strings.HasPrefix(original, "%") && strings.HasSuffix(original, "%")) {
		return true
	}
	for _, prefix := range []string{
		"env:", "secret://", "vault://", "kv://", "keyvault://",
		"aws-secretsmanager://", "gcp-secretmanager://", "@microsoft.keyvault(",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	detector.Register(&StructuredConfigDetector{})
}

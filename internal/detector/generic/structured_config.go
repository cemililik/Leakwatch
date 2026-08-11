package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/entropy"
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
// fields of JSON/JSONC, YAML, TOML, XML and dotenv configuration files. Each
// syntax has a bounded adapter; formats are not fed through one permissive
// cross-format regexp. Explicit field context can therefore detect human-style
// and short secrets without weakening the generic detector's false-positive
// gates.
type StructuredConfigDetector struct{}

func (d *StructuredConfigDetector) ID() string          { return "structured-config-secret" }
func (d *StructuredConfigDetector) Description() string { return "Structured Configuration Secret" }
func (d *StructuredConfigDetector) Severity() finding.Severity {
	return finding.SeverityHigh
}

func (d *StructuredConfigDetector) Keywords() []string {
	// JSON permits escaped object keys (for example "Pass\u0077ord"), and the
	// supported role vocabulary has many casing/separator forms. No finite raw
	// substring list can preserve Scan/matcher parity for all of them. Running
	// the bounded lexer for every text chunk is therefore a correctness choice,
	// not an omitted optimization.
	return nil
}

// FallbackOnSpecializedOverlap marks this context detector as a fallback when a
// specialized detector identifies the same source value. The engine keeps the
// provider-specific severity, verification and remediation in that case.
func (d *StructuredConfigDetector) FallbackOnSpecializedOverlap() bool { return true }

func (d *StructuredConfigDetector) Scan(ctx context.Context, data []byte) []detector.RawFinding {
	scanData, baseOffset := stripUTF8BOM(data)
	trimmed := bytes.TrimSpace(scanData)
	if len(trimmed) == 0 {
		return nil
	}
	var findings []detector.RawFinding
	switch trimmed[0] {
	case '{':
		findings = d.scanJSON(ctx, scanData)
	case '[':
		firstLine := trimmed
		if lineEnd := bytes.IndexByte(firstLine, '\n'); lineEnd >= 0 {
			firstLine = firstLine[:lineEnd]
		}
		if _, tomlSection := parseTOMLSection(firstLine); tomlSection {
			findings = d.scanLineConfig(ctx, scanData)
			break
		}
		findings = d.scanJSON(ctx, scanData)
	case '<':
		findings = d.scanXML(ctx, scanData)
	default:
		findings = d.scanLineConfig(ctx, scanData)
	}
	if baseOffset != 0 {
		for i := range findings {
			findings[i].ByteStart += baseOffset
			findings[i].ByteEnd += baseOffset
		}
	}
	return findings
}

func stripUTF8BOM(data []byte) ([]byte, int) {
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return data[3:], 3
	}
	return data, 0
}

func (d *StructuredConfigDetector) scanJSON(ctx context.Context, data []byte) []detector.RawFinding {
	tokens, candidates, complete := lexJSONLike(ctx, data)
	if !complete || len(candidates) == 0 {
		return nil
	}

	paths := buildJSONPaths(tokens)
	findings := make([]detector.RawFinding, 0, len(candidates))
	for _, candidate := range candidates {
		keyToken, valueToken := candidate.key, candidate.value
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

type structuredCandidate struct {
	key   jsonToken
	value jsonToken
}

// lexJSONLike tokenizes only the JSON structure needed for key/value
// extraction. It preserves byte offsets, skips // and /* */ comments, accepts
// trailing commas at the parser layer, and retains at most
// maxStructuredTokens tokens for path reconstruction. Candidate extraction
// continues through the entire bounded input even after that retention cap, so
// a large valid prefix cannot hide a secret near the end of a file.
func lexJSONLike(ctx context.Context, data []byte) ([]jsonToken, []structuredCandidate, bool) {
	lexer := jsonLikeLexer{
		data: data, tokens: make([]jsonToken, 0, minInt(len(data)/8, 4_096)),
		candidates: make([]structuredCandidate, 0, 8),
	}
	for position := 0; position < len(data); {
		if ctx.Err() != nil {
			return nil, nil, false
		}
		next, complete := lexer.scanToken(ctx, position)
		if !complete {
			return nil, nil, false
		}
		position = next
	}
	return lexer.tokens, lexer.candidates, true
}

type jsonLikeLexer struct {
	data          []byte
	tokens        []jsonToken
	candidates    []structuredCandidate
	previous      [2]jsonToken
	previousCount int
	depth         int
}

func (l *jsonLikeLexer) scanToken(ctx context.Context, position int) (int, bool) {
	value := l.data[position]
	if value == ' ' || value == '\t' || value == '\r' || value == '\n' {
		return position + 1, true
	}
	if value == '/' {
		return l.scanCommentOrSlash(ctx, position)
	}
	if value == '"' {
		token, next, ok, complete := scanJSONString(ctx, l.data, position, l.depth)
		if ok {
			l.emit(token)
		}
		return next, complete
	}
	if kind, opening, closing, ok := jsonStructuralToken(value); ok {
		if closing && l.depth > 0 {
			l.depth--
		}
		l.emit(jsonToken{kind: kind, start: position, end: position + 1, depth: l.depth})
		if opening {
			l.depth++
		}
		return position + 1, true
	}
	return l.scanOtherToken(ctx, position)
}

func jsonStructuralToken(value byte) (jsonTokenKind, bool, bool, bool) {
	switch value {
	case ':':
		return jsonColon, false, false, true
	case ',':
		return jsonComma, false, false, true
	case '{':
		return jsonObjectStart, true, false, true
	case '[':
		return jsonArrayStart, true, false, true
	case '}':
		return jsonObjectEnd, false, true, true
	case ']':
		return jsonArrayEnd, false, true, true
	default:
		return jsonOther, false, false, false
	}
}

func (l *jsonLikeLexer) scanCommentOrSlash(ctx context.Context, position int) (int, bool) {
	if position+1 >= len(l.data) || (l.data[position+1] != '/' && l.data[position+1] != '*') {
		l.emit(jsonToken{kind: jsonOther, start: position, end: position + 1, depth: l.depth})
		return position + 1, true
	}
	lineComment := l.data[position+1] == '/'
	position += 2
	nextContextCheck := position + 4_096
	for position < len(l.data) {
		if lineComment && l.data[position] == '\n' {
			break
		}
		if !lineComment && position+1 < len(l.data) && l.data[position] == '*' && l.data[position+1] == '/' {
			return position + 2, true
		}
		if position >= nextContextCheck {
			if ctx.Err() != nil {
				return position, false
			}
			nextContextCheck = position + 4_096
		}
		position++
	}
	return position, true
}

func (l *jsonLikeLexer) scanOtherToken(ctx context.Context, position int) (int, bool) {
	start := position
	nextContextCheck := position + 4_096
	for position < len(l.data) && !isJSONDelimiter(l.data[position]) {
		if position >= nextContextCheck {
			if ctx.Err() != nil {
				return position, false
			}
			nextContextCheck = position + 4_096
		}
		position++
	}
	if position == start {
		position++
	}
	l.emit(jsonToken{kind: jsonOther, start: start, end: position, depth: l.depth})
	return position, true
}

func (l *jsonLikeLexer) emit(token jsonToken) {
	if token.kind == jsonString {
		decoded, ok := decodeJSONString(l.data, token)
		if !ok {
			token.kind = jsonOther
		} else {
			token.text = decoded
		}
	}
	if l.isSecretCandidate(token) {
		l.candidates = append(l.candidates, structuredCandidate{key: l.previous[0], value: token})
	}
	if len(l.tokens) < maxStructuredTokens {
		l.tokens = append(l.tokens, token)
	}
	if l.previousCount < 2 {
		l.previous[l.previousCount] = token
		l.previousCount++
		return
	}
	l.previous[0], l.previous[1] = l.previous[1], token
}

func (l *jsonLikeLexer) isSecretCandidate(token jsonToken) bool {
	return l.previousCount == 2 && l.previous[0].kind == jsonString &&
		l.previous[1].kind == jsonColon && token.kind == jsonString &&
		l.previous[0].depth <= maxStructuredDepth && token.depth <= maxStructuredDepth &&
		isHighConfidenceSecretKey(l.previous[0].text) &&
		isContextSecretValue(l.previous[0].text, token.text) && len(l.candidates) < maxStructuredFindings
}

func scanJSONString(ctx context.Context, data []byte, start, depth int) (jsonToken, int, bool, bool) {
	i := start + 1
	nextContextCheck := i + 4_096
	tooLong := false
	for i < len(data) {
		if i >= nextContextCheck {
			if ctx.Err() != nil {
				return jsonToken{}, i, false, false
			}
			nextContextCheck = i + 4_096
		}
		if i-start-1 > maxStructuredStringLen {
			tooLong = true
		}
		switch data[i] {
		case '\\':
			if i+1 >= len(data) {
				return jsonToken{}, len(data), false, true
			}
			i += 2
		case '"':
			end := i + 1
			if tooLong || i-start-1 > maxStructuredStringLen {
				return jsonToken{}, end, false, true
			}
			return jsonToken{
				kind:         jsonString,
				start:        start,
				end:          end,
				contentStart: start + 1,
				contentEnd:   i,
				depth:        depth,
			}, end, true, true
		default:
			i++
		}
	}
	return jsonToken{}, len(data), false, true
}

func decodeJSONString(data []byte, token jsonToken) (string, bool) {
	encoded := data[token.start:token.end]
	if !utf8.Valid(encoded) || !hasValidJSONSurrogates(encoded) {
		return "", false
	}
	var decoded string
	err := json.Unmarshal(encoded, &decoded)
	return decoded, err == nil && utf8.ValidString(decoded)
}

func hasValidJSONSurrogates(encoded []byte) bool {
	for i := 1; i+1 < len(encoded); i++ {
		if encoded[i] != '\\' {
			continue
		}
		i++
		if encoded[i] != 'u' {
			continue
		}
		first, ok := decodeHexQuad(encoded, i+1)
		if !ok {
			return false
		}
		i += 4
		switch {
		case first >= 0xd800 && first <= 0xdbff:
			if i+6 >= len(encoded) || encoded[i+1] != '\\' || encoded[i+2] != 'u' {
				return false
			}
			second, secondOK := decodeHexQuad(encoded, i+3)
			if !secondOK || second < 0xdc00 || second > 0xdfff {
				return false
			}
			i += 6
		case first >= 0xdc00 && first <= 0xdfff:
			return false
		}
	}
	return true
}

func decodeHexQuad(data []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(data) {
		return 0, false
	}
	var value uint16
	for _, b := range data[start : start+4] {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value += uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value += uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value += uint16(b-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
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
	if p.pos >= len(p.tokens) {
		return
	}
	if depth > maxStructuredDepth {
		// Every parser call must either consume input or be at EOF. Advancing at
		// the bound prevents a deeply nested non-empty array from repeatedly
		// presenting the same token to parseArray.
		p.pos++
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
		b.WriteString(safeConfigPathComponent(component))
	}
	return b.String()
}

// safeConfigPathComponent keeps untrusted structural names useful as metadata
// without allowing a secret-shaped dynamic key, control characters, or an
// attacker-sized name to be copied into output and logs. Detection continues to
// classify the original leaf key; this function affects display metadata only.
func safeConfigPathComponent(component string) string {
	const maxComponentBytes = 128
	if component == "" || len(component) > maxComponentBytes || !utf8.ValidString(component) {
		return "<dynamic-key>"
	}
	for _, r := range component {
		if unicode.IsControl(r) || !unicode.IsGraphic(r) {
			return "<dynamic-key>"
		}
	}
	if len(component) >= 20 && entropy.Calculate([]byte(component)) >= minEntropy {
		return "<dynamic-key>"
	}
	return component
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

func isContextSecretValue(key, value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < minContextSecretLength || len(trimmed) > maxStructuredStringLen {
		return false
	}
	lower := strings.ToLower(trimmed)
	switch lower {
	case "password", "secret", "string", "redacted", "masked", "changeme", "change-me", "change_me", "dummy",
		"example", "sample", "notset", "not-set", "none", "null", "default", "test", "dev", "local",
		"true", "false", "yes", "no", "on", "off",
		"your-secret", "your_secret", "your-password", "your_password", "your_key_here", "your-key-here",
		"replace_me", "todo", "fixme", "placeholder", "example-secret":
		return false
	}
	if isDegenerateValue([]byte(trimmed)) || isBareReference([]byte(trimmed)) {
		return false
	}
	if isExternalSecretReference(lower, trimmed) {
		return false
	}
	if isKeyMaterialReference(canonicalConfigKey(key), lower) {
		return false
	}
	return true
}

func isExternalSecretReference(lower, original string) bool {
	if (strings.HasPrefix(original, "${") && strings.HasSuffix(original, "}")) ||
		(strings.HasPrefix(original, "{{") && strings.HasSuffix(original, "}}")) ||
		(strings.HasPrefix(original, "%") && strings.HasSuffix(original, "%")) ||
		(strings.HasPrefix(original, "$(") && strings.HasSuffix(original, ")")) ||
		isDollarReference(original) || isAngleReference(original) {
		return true
	}
	if isYAMLAliasReference(original) {
		return true
	}
	if isFilesystemReference(lower) {
		return true
	}
	for _, prefix := range []string{
		"env:", "secret://", "vault://", "kv://", "keyvault://",
		"aws-secretsmanager://", "gcp-secretmanager://", "op://", "1password://",
		"@microsoft.keyvault(", "os.getenv(", "os.environ[", "process.env.",
		"environment.getenvironmentvariable(", "system.getenv(", "config.get(",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isYAMLAliasReference(value string) bool {
	if len(value) < 2 || value[0] != '*' {
		return false
	}
	for _, r := range value[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func isFilesystemReference(lower string) bool {
	for _, prefix := range []string{
		"/", "./", "../", "~/", "\\\\", "file:",
		"secrets/", ".secrets/", "certs/", "certificates/", "run/secrets/", "var/run/secrets/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if len(lower) >= 3 && lower[1] == ':' && lower[0] >= 'a' && lower[0] <= 'z' &&
		(lower[2] == '/' || lower[2] == '\\') {
		return true
	}
	if !strings.ContainsAny(lower, "/\\") {
		return false
	}
	for _, suffix := range []string{
		".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".crt", ".cer",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func isDollarReference(value string) bool {
	if !strings.HasPrefix(value, "$") || len(value) < 2 {
		return false
	}
	for _, r := range value[1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != ':' {
			return false
		}
	}
	return true
}

func isAngleReference(value string) bool {
	if len(value) < 3 || value[0] != '<' || value[len(value)-1] != '>' {
		return false
	}
	for _, r := range value[1 : len(value)-1] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != ' ' {
			return false
		}
	}
	return true
}

func isKeyMaterialReference(key, lower string) bool {
	switch key {
	case "privatekey", "masterkey", "encryptionkey":
	default:
		return false
	}
	for _, prefix := range []string{
		"pkcs11:", "arn:aws:kms:", "alias/",
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

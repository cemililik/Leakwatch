package generic

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type lineConfigFormat string

const (
	formatDotenv lineConfigFormat = "dotenv"
	formatTOML   lineConfigFormat = "toml"
	formatYAML   lineConfigFormat = "yaml"
)

type lineAssignment struct {
	key                  string
	inlinePath           []string
	value                string
	valueStart, valueEnd int
	indent               int
	hasValue             bool
	blockStyle           byte
}

type yamlSignal struct {
	indent   int
	hasValue bool
}

func (d *StructuredConfigDetector) scanLineConfig(ctx context.Context, data []byte) []detector.RawFinding {
	if !utf8.Valid(data) || ctx.Err() != nil {
		return nil
	}
	format, confident := detectLineConfigFormat(ctx, data)
	if !confident {
		return nil
	}
	scanner := lineConfigScanner{detector: d, ctx: ctx, data: data, format: format}
	return scanner.scan()
}

type lineConfigScanner struct {
	detector *StructuredConfigDetector
	ctx      context.Context
	data     []byte
	format   lineConfigFormat
	findings []detector.RawFinding
	yamlPath []yamlPathComponent
	tomlPath []string
}

func (s *lineConfigScanner) scan() []detector.RawFinding {
	s.findings = make([]detector.RawFinding, 0, 4)
	for offset := 0; offset < len(s.data); {
		lineEnd, complete := contextLineEnd(s.ctx, s.data, offset)
		if !complete {
			return nil
		}
		offset = s.processLine(offset, lineEnd)
	}
	return s.findings
}

func (s *lineConfigScanner) processLine(offset, lineEnd int) int {
	nextOffset := nextLineOffset(lineEnd, len(s.data))
	line := bytes.TrimSuffix(s.data[offset:lineEnd], []byte{'\r'})
	if s.format == formatTOML {
		if section, ok := parseTOMLSection(line); ok {
			s.tomlPath = section
			return nextOffset
		}
	}
	assignment, ok := parseLineAssignment(line, offset, s.format)
	if !ok {
		return nextOffset
	}
	path, terminal := s.assignmentPath(assignment)
	if terminal {
		return nextOffset
	}
	if s.format == formatYAML && assignment.blockStyle != 0 {
		var scalarOK bool
		assignment.value, assignment.valueStart, assignment.valueEnd, nextOffset, scalarOK = parseYAMLBlockScalar(s.ctx, s.data, nextOffset, assignment.indent, assignment.blockStyle)
		if !scalarOK {
			return nextOffset
		}
	}
	s.appendFinding(path, assignment)
	return nextOffset
}

func (s *lineConfigScanner) assignmentPath(assignment lineAssignment) ([]string, bool) {
	switch s.format {
	case formatYAML:
		for len(s.yamlPath) > 0 && s.yamlPath[len(s.yamlPath)-1].indent >= assignment.indent {
			s.yamlPath = s.yamlPath[:len(s.yamlPath)-1]
		}
		path := yamlComponents(s.yamlPath)
		if !assignment.hasValue {
			s.yamlPath = append(s.yamlPath, yamlPathComponent{indent: assignment.indent, key: assignment.key})
			return path, true
		}
		return path, false
	case formatTOML:
		return append(append([]string(nil), s.tomlPath...), assignment.inlinePath...), false
	default:
		return nil, false
	}
}

func (s *lineConfigScanner) appendFinding(path []string, assignment lineAssignment) {
	if !assignment.hasValue || !isHighConfidenceSecretKey(assignment.key) ||
		!isContextSecretValue(assignment.key, assignment.value) || len(s.findings) >= maxStructuredFindings {
		return
	}
	raw := bytes.Clone(s.data[assignment.valueStart:assignment.valueEnd])
	s.findings = append(s.findings, detector.RawFinding{
		DetectorID: s.detector.ID(), Raw: raw, Redacted: detector.RedactBytes(raw),
		ExtraData: map[string]string{
			"key_name": assignment.key, "key_path": joinJSONPath(appendJSONPath(path, assignment.key)),
			"config_format": string(s.format),
		},
		ByteStart: assignment.valueStart, ByteEnd: assignment.valueEnd,
	})
}

func detectLineConfigFormat(ctx context.Context, data []byte) (lineConfigFormat, bool) {
	signals := lineConfigSignals{pendingYAMLParentIndent: -1}
	for offset := 0; offset < len(data); {
		lineEnd, complete := contextLineEnd(ctx, data, offset)
		if !complete {
			return "", false
		}
		line := bytes.TrimSpace(data[offset:lineEnd])
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) || bytes.HasPrefix(line, []byte("//")) {
			offset = nextLineOffset(lineEnd, len(data))
			continue
		}
		if section, ok := parseTOMLSection(line); ok && len(section) > 0 {
			return formatTOML, true
		}
		if bytes.Equal(line, []byte("---")) {
			signals.hasYAMLDocumentMarker = true
			offset = nextLineOffset(lineEnd, len(data))
			continue
		}
		signals.observe(data[offset:lineEnd], line, offset)
		offset = nextLineOffset(lineEnd, len(data))
	}
	return signals.detectedFormat()
}

type lineConfigSignals struct {
	yamlSignalCount, dotenvAssignments, tomlAssignments int
	pendingYAMLParentIndent                             int
	yamlNested, yamlInvalid, dotenvInvalid, tomlInvalid bool
	hasYAMLDocumentMarker                               bool
}

func (s *lineConfigSignals) observe(rawLine, trimmedLine []byte, offset int) {
	if signal, ok := yamlMappingSignal(rawLine); ok {
		s.observeYAML(signal)
		s.dotenvInvalid = true
	} else if isDotenvAssignment(trimmedLine) {
		s.dotenvAssignments++
		s.yamlInvalid = true
	} else {
		s.dotenvInvalid, s.yamlInvalid = true, true
	}
	if _, ok := parseLineAssignment(rawLine, offset, formatTOML); ok {
		s.tomlAssignments++
	} else {
		s.tomlInvalid = true
	}
}

func (s *lineConfigSignals) observeYAML(signal yamlSignal) {
	s.yamlSignalCount++
	if s.pendingYAMLParentIndent >= 0 {
		if signal.indent > s.pendingYAMLParentIndent {
			s.yamlNested = true
		}
		if signal.indent <= s.pendingYAMLParentIndent {
			s.pendingYAMLParentIndent = -1
		}
	}
	if !signal.hasValue {
		s.pendingYAMLParentIndent = signal.indent
	}
}

func (s lineConfigSignals) detectedFormat() (lineConfigFormat, bool) {
	if (s.hasYAMLDocumentMarker && s.yamlSignalCount > 0) || s.yamlNested ||
		(s.yamlSignalCount >= 2 && !s.yamlInvalid) {
		return formatYAML, true
	}
	if s.dotenvAssignments > 0 && !s.dotenvInvalid && s.yamlSignalCount == 0 {
		return formatDotenv, true
	}
	// Without source-extension metadata a lone `password = "..."` line is
	// indistinguishable from source code. Requiring a complete, multi-assignment
	// document preserves support for sectionless TOML while keeping that common
	// code shape out of the high-confidence detector.
	if s.tomlAssignments >= 2 && !s.tomlInvalid && s.yamlSignalCount == 0 {
		return formatTOML, true
	}
	return "", false
}

func contextLineEnd(ctx context.Context, data []byte, offset int) (int, bool) {
	const checkBytes = 4 * 1024
	for start := offset; start < len(data); {
		if ctx.Err() != nil {
			return 0, false
		}
		end := minInt(start+checkBytes, len(data))
		if relative := bytes.IndexByte(data[start:end], '\n'); relative >= 0 {
			return start + relative, true
		}
		start = end
	}
	return len(data), ctx.Err() == nil
}

func yamlMappingSignal(line []byte) (yamlSignal, bool) {
	trimmed := bytes.TrimLeft(line, " \t")
	indent := visualIndent(line[:len(line)-len(trimmed)])
	if bytes.HasPrefix(trimmed, []byte("- ")) {
		trimmed = bytes.TrimLeft(trimmed[2:], " \t")
	}
	index := bytes.IndexByte(trimmed, ':')
	if index <= 0 || !isPlainConfigKey(bytes.TrimSpace(trimmed[:index])) {
		return yamlSignal{}, false
	}
	remainder := bytes.TrimSpace(trimmed[index+1:])
	return yamlSignal{indent: indent, hasValue: len(remainder) > 0 && remainder[0] != '#'}, true
}

func hasNestedYAMLSignals(signals []yamlSignal) bool {
	for i, parent := range signals {
		if parent.hasValue {
			continue
		}
		for _, child := range signals[i+1:] {
			if child.indent > parent.indent {
				return true
			}
			if child.indent <= parent.indent {
				break
			}
		}
	}
	return false
}

func isDotenvAssignment(line []byte) bool {
	line = bytes.TrimSpace(line)
	if bytes.HasPrefix(line, []byte("export ")) {
		line = bytes.TrimSpace(line[len("export "):])
	}
	index := bytes.IndexByte(line, '=')
	if index <= 0 {
		return false
	}
	key := bytes.TrimSpace(line[:index])
	if len(key) == 0 || key[0] < 'A' || key[0] > 'Z' {
		return false
	}
	for _, b := range key[1:] {
		if (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' {
			return false
		}
	}
	return len(bytes.TrimSpace(line[index+1:])) > 0
}

func parseLineAssignment(line []byte, base int, format lineConfigFormat) (lineAssignment, bool) {
	trimmed, indentBytes, originalIndent, ok := normalizeAssignmentLine(line, format)
	if !ok {
		return lineAssignment{}, false
	}
	keyPath, delimiterIndex, ok := assignmentKeyPath(trimmed, format)
	if !ok {
		return lineAssignment{}, false
	}
	key := keyPath[len(keyPath)-1]
	inlinePath := keyPath[:len(keyPath)-1]
	valueBase := base + indentBytes + delimiterIndex + 1
	valueBytes := trimmed[delimiterIndex+1:]
	return assignmentFromValue(key, inlinePath, valueBytes, valueBase, originalIndent, format)
}

func normalizeAssignmentLine(line []byte, format lineConfigFormat) ([]byte, int, int, bool) {
	trimmed := bytes.TrimLeft(line, " \t")
	indentBytes := len(line) - len(trimmed)
	originalIndent := visualIndent(line[:indentBytes])
	if len(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';' || bytes.HasPrefix(trimmed, []byte("//")) {
		return nil, 0, 0, false
	}
	prefix := ""
	if format == formatYAML && bytes.HasPrefix(trimmed, []byte("- ")) {
		prefix = "- "
	} else if format == formatDotenv && bytes.HasPrefix(trimmed, []byte("export ")) {
		prefix = "export "
	}
	if prefix != "" {
		rest := trimmed[len(prefix):]
		withoutSpacing := bytes.TrimLeft(rest, " \t")
		indentBytes += len(prefix) + len(rest) - len(withoutSpacing)
		trimmed = withoutSpacing
	}
	return trimmed, indentBytes, originalIndent, true
}

func assignmentKeyPath(trimmed []byte, format lineConfigFormat) ([]string, int, bool) {
	delimiter := byte('=')
	if format == formatYAML {
		delimiter = ':'
	}
	index := bytes.IndexByte(trimmed, delimiter)
	if index <= 0 {
		return nil, 0, false
	}
	keyBytes := bytes.TrimSpace(trimmed[:index])
	if format == formatTOML {
		path, ok := parseTOMLDottedKey(keyBytes)
		return path, index, ok
	}
	if !isPlainConfigKey(keyBytes) {
		return nil, 0, false
	}
	return []string{string(keyBytes)}, index, true
}

func assignmentFromValue(
	key string,
	inlinePath []string,
	valueBytes []byte,
	valueBase, originalIndent int,
	format lineConfigFormat,
) (lineAssignment, bool) {
	trimmedValue := bytes.TrimSpace(valueBytes)
	if len(trimmedValue) == 0 || (format == formatYAML && trimmedValue[0] == '#') {
		return lineAssignment{key: key, inlinePath: inlinePath, indent: originalIndent}, true
	}
	if format == formatYAML && (trimmedValue[0] == '|' || trimmedValue[0] == '>') {
		if !isYAMLBlockIndicator(trimmedValue) {
			return lineAssignment{}, false
		}
		return lineAssignment{
			key: key, inlinePath: inlinePath, indent: originalIndent,
			hasValue: true, blockStyle: trimmedValue[0],
		}, true
	}
	value, start, end, ok := parseLineScalar(valueBytes, valueBase, format)
	if !ok {
		return lineAssignment{}, false
	}
	return lineAssignment{
		key:        key,
		inlinePath: inlinePath,
		value:      value,
		valueStart: start,
		valueEnd:   end,
		indent:     originalIndent,
		hasValue:   true,
	}, true
}

func parseTOMLDottedKey(raw []byte) ([]string, bool) {
	parts := bytes.Split(raw, []byte("."))
	if len(parts) == 0 {
		return nil, false
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = bytes.TrimSpace(part)
		if len(part) == 0 {
			return nil, false
		}
		if (part[0] == '\'' || part[0] == '"') && len(part) >= 2 && part[len(part)-1] == part[0] {
			value, _, _, ok := parseLineScalar(part, 0, formatTOML)
			if !ok || value == "" {
				return nil, false
			}
			result = append(result, value)
			continue
		}
		if !isPlainConfigKey(part) {
			return nil, false
		}
		result = append(result, string(part))
	}
	return result, true
}

func isYAMLBlockIndicator(value []byte) bool {
	value = bytes.TrimSpace(value)
	if len(value) == 0 || (value[0] != '|' && value[0] != '>') {
		return false
	}
	i := 1
	for i < len(value) && (value[i] == '+' || value[i] == '-' || (value[i] >= '1' && value[i] <= '9')) {
		i++
	}
	rest := bytes.TrimSpace(value[i:])
	return len(rest) == 0 || rest[0] == '#'
}

func parseYAMLBlockScalar(
	ctx context.Context,
	data []byte,
	offset int,
	parentIndent int,
	style byte,
) (string, int, int, int, bool) {
	lines, contentIndentBytes, nextOffset, ok := collectYAMLBlockLines(ctx, data, offset, parentIndent)
	if !ok {
		return "", 0, 0, nextOffset, false
	}
	decoded, first, last, ok := decodeYAMLBlockLines(data, lines, contentIndentBytes, style)
	return decoded, first, last, nextOffset, ok
}

type yamlBlockLine struct {
	start, end  int
	indentBytes int
	blank       bool
}

func collectYAMLBlockLines(
	ctx context.Context,
	data []byte,
	offset, parentIndent int,
) ([]yamlBlockLine, int, int, bool) {
	lines := make([]yamlBlockLine, 0, 4)
	contentIndentBytes := -1
	for offset < len(data) {
		lineEnd, complete := contextLineEnd(ctx, data, offset)
		if !complete {
			return nil, 0, len(data), false
		}
		line := data[offset:lineEnd]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		trimmed := bytes.TrimSpace(line)
		indentBytes := len(line) - len(bytes.TrimLeft(line, " \t"))
		if bytes.IndexByte(line[:indentBytes], '\t') >= 0 {
			return nil, 0, offset, false
		}
		indent := visualIndent(line[:indentBytes])
		if len(trimmed) > 0 && indent <= parentIndent {
			break
		}
		if len(trimmed) > 0 {
			if contentIndentBytes < 0 || indentBytes < contentIndentBytes {
				contentIndentBytes = indentBytes
			}
		}
		lines = append(lines, yamlBlockLine{
			start: offset, end: offset + len(line), indentBytes: indentBytes, blank: len(trimmed) == 0,
		})
		offset = nextLineOffset(lineEnd, len(data))
	}
	if contentIndentBytes <= parentIndent || len(lines) == 0 {
		return nil, 0, offset, false
	}
	return lines, contentIndentBytes, offset, true
}

func decodeYAMLBlockLines(data []byte, lines []yamlBlockLine, contentIndentBytes int, style byte) (string, int, int, bool) {
	first, last := -1, -1
	var decoded strings.Builder
	previousBlank := false
	for _, line := range lines {
		if line.blank {
			if decoded.Len() > 0 {
				decoded.WriteByte('\n')
			}
			previousBlank = true
			continue
		}
		contentStart := line.start + contentIndentBytes
		if contentStart > line.end {
			return "", 0, 0, false
		}
		if first < 0 {
			first = contentStart
		}
		if decoded.Len() > 0 && !previousBlank {
			if style == '|' {
				decoded.WriteByte('\n')
			} else {
				decoded.WriteByte(' ')
			}
		}
		decoded.Write(data[contentStart:line.end])
		last = line.end
		previousBlank = false
	}
	if first < 0 || last <= first || decoded.Len() > maxStructuredStringLen {
		return "", 0, 0, false
	}
	return decoded.String(), first, last, true
}

func parseLineScalar(value []byte, base int, format lineConfigFormat) (string, int, int, bool) {
	left := len(value) - len(bytes.TrimLeft(value, " \t"))
	value = value[left:]
	base += left
	if len(value) == 0 || value[0] == '|' || value[0] == '>' || value[0] == '[' || value[0] == '{' {
		return "", 0, 0, false
	}
	if format == formatYAML && value[0] == '&' {
		anchorEnd := bytes.IndexAny(value, " \t")
		if anchorEnd <= 1 {
			return "", 0, 0, false
		}
		rest := value[anchorEnd:]
		return parseLineScalar(rest, base+anchorEnd, format)
	}
	if value[0] == '\'' || value[0] == '"' {
		return parseQuotedLineScalar(value, base, format)
	}
	return parsePlainLineScalar(value, base, format)
}

func parseQuotedLineScalar(value []byte, base int, format lineConfigFormat) (string, int, int, bool) {
	quote := value[0]
	end := findClosingQuoteForFormat(value, quote, format)
	if end <= 0 || !onlyWhitespaceOrComment(value[end+1:]) {
		return "", 0, 0, false
	}
	raw := value[1:end]
	if len(raw) > maxStructuredStringLen {
		return "", 0, 0, false
	}
	decoded, ok := decodeQuotedLineScalar(value[:end+1], raw, quote, format)
	if !ok {
		return "", 0, 0, false
	}
	return decoded, base + 1, base + end, true
}

func decodeQuotedLineScalar(quoted, raw []byte, quote byte, format lineConfigFormat) (string, bool) {
	if quote == '\'' {
		decoded := string(raw)
		if format == formatYAML {
			decoded = strings.ReplaceAll(decoded, "''", "'")
		}
		return decoded, true
	}
	var decoded string
	var err error
	switch format {
	case formatYAML:
		err = yaml.Unmarshal(quoted, &decoded)
	case formatTOML:
		var scalar struct {
			Value string `toml:"value"`
		}
		err = toml.Unmarshal(append([]byte("value = "), quoted...), &scalar)
		decoded = scalar.Value
	default:
		decoded, err = strconv.Unquote(string(quoted))
	}
	return decoded, err == nil
}

func parsePlainLineScalar(value []byte, base int, format lineConfigFormat) (string, int, int, bool) {
	end := len(value)
	for i := 1; i < len(value); i++ {
		if value[i] == '#' && (value[i-1] == ' ' || value[i-1] == '\t') {
			end = i
			break
		}
	}
	raw := bytes.TrimRight(value[:end], " \t\r")
	if len(raw) == 0 || len(raw) > maxStructuredStringLen || format == formatTOML {
		return "", 0, 0, false
	}
	return string(raw), base, base + len(raw), true
}

func findClosingQuote(value []byte, quote byte) int {
	return findClosingQuoteForFormat(value, quote, "")
}

func findClosingQuoteForFormat(value []byte, quote byte, format lineConfigFormat) int {
	for i := 1; i < len(value); i++ {
		if value[i] != quote {
			continue
		}
		if quote == '\'' && format == formatYAML &&
			i+1 < len(value) && value[i+1] == quote {
			i++
			continue
		}
		if quote == '"' {
			backslashes := 0
			for j := i - 1; j >= 0 && value[j] == '\\'; j-- {
				backslashes++
			}
			if backslashes%2 == 1 {
				continue
			}
		}
		return i
	}
	return -1
}

func onlyWhitespaceOrComment(value []byte) bool {
	value = bytes.TrimSpace(value)
	return len(value) == 0 || value[0] == '#'
}

func isPlainConfigKey(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, r := range string(value) {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

func parseTOMLSection(line []byte) ([]string, bool) {
	trimmed := bytes.TrimSpace(line)
	if comment := bytes.IndexByte(trimmed, '#'); comment >= 0 {
		trimmed = bytes.TrimSpace(trimmed[:comment])
	}
	if len(trimmed) < 3 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' || trimmed[1] == '[' {
		return nil, false
	}
	section := strings.TrimSpace(string(trimmed[1 : len(trimmed)-1]))
	if section == "" {
		return nil, false
	}
	parts := strings.Split(section, ".")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if !isPlainConfigKey([]byte(parts[i])) {
			return nil, false
		}
	}
	return parts, true
}

type yamlPathComponent struct {
	indent int
	key    string
}

func yamlComponents(path []yamlPathComponent) []string {
	out := make([]string, len(path))
	for i := range path {
		out[i] = path[i].key
	}
	return out
}

func visualIndent(prefix []byte) int {
	indent := 0
	for _, b := range prefix {
		if b == '\t' {
			indent += 8
		} else {
			indent++
		}
	}
	return indent
}

func nextLineOffset(lineEnd, dataLen int) int {
	if lineEnd < dataLen {
		return lineEnd + 1
	}
	return dataLen
}

type xmlFrame struct {
	name         string
	path         []string
	contentStart int
	textStart    int
	textEnd      int
	text         []byte
	hasChild     bool
	validText    bool
}

type xmlAttributeSpan struct {
	name       string
	value      string
	valueStart int
	valueEnd   int
}

func (d *StructuredConfigDetector) scanXML(ctx context.Context, data []byte) []detector.RawFinding {
	if !utf8.Valid(data) || ctx.Err() != nil {
		return nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	state := xmlScanState{detector: d, data: data, stack: make([]xmlFrame, 0, 8), findings: make([]detector.RawFinding, 0, 4)}
	tokenCount := 0
	for {
		if tokenCount&255 == 0 && ctx.Err() != nil {
			return nil
		}
		tokenStart := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil || tokenCount >= maxStructuredTokens {
			return nil
		}
		tokenCount++
		if !state.consume(token, tokenStart, int(decoder.InputOffset())) {
			return nil
		}
	}
	if len(state.stack) != 0 {
		return nil
	}
	return state.findings
}

type xmlScanState struct {
	detector *StructuredConfigDetector
	data     []byte
	stack    []xmlFrame
	findings []detector.RawFinding
}

func (s *xmlScanState) consume(token xml.Token, start, end int) bool {
	switch value := token.(type) {
	case xml.StartElement:
		return s.pushElement(value, start, end)
	case xml.CharData:
		s.appendCharacterData(value, start, end)
	case xml.Comment, xml.Directive, xml.ProcInst:
		s.invalidateCurrentText()
	case xml.EndElement:
		return s.closeElement(value)
	}
	return true
}

func (s *xmlScanState) pushElement(element xml.StartElement, start, end int) bool {
	if len(s.stack) >= maxStructuredDepth {
		return false
	}
	path := []string(nil)
	if len(s.stack) > 0 {
		s.stack[len(s.stack)-1].hasChild = true
		path = append(path, s.stack[len(s.stack)-1].path...)
	}
	path = append(path, element.Name.Local)
	attributes, ok := parseXMLAttributeSpans(s.data[start:end], start, element.Attr)
	if !ok {
		return false
	}
	s.findings = appendXMLAttributeFindings(s.detector, s.findings, s.data, path, attributes)
	s.stack = append(s.stack, xmlFrame{
		name: element.Name.Local, path: path, contentStart: end, textStart: -1, validText: true,
	})
	return true
}

func (s *xmlScanState) appendCharacterData(value xml.CharData, start, end int) {
	if len(s.stack) == 0 {
		return
	}
	frame := &s.stack[len(s.stack)-1]
	if bytes.HasPrefix(s.data[start:end], []byte("<![CDATA[")) && bytes.HasSuffix(s.data[start:end], []byte("]]>")) {
		start += len("<![CDATA[")
		end -= len("]]>")
	}
	if frame.textStart < 0 {
		frame.textStart = start
	}
	frame.textEnd = end
	frame.text = append(frame.text, value...)
}

func (s *xmlScanState) invalidateCurrentText() {
	if len(s.stack) > 0 {
		s.stack[len(s.stack)-1].validText = false
	}
}

func (s *xmlScanState) closeElement(element xml.EndElement) bool {
	if len(s.stack) == 0 || s.stack[len(s.stack)-1].name != element.Name.Local {
		return false
	}
	frame := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	if frame.hasChild || !frame.validText || frame.textStart < frame.contentStart {
		return true
	}
	decoded := strings.TrimSpace(string(frame.text))
	start, end := trimSpaceBounds(s.data, frame.textStart, frame.textEnd)
	if start >= end || !isHighConfidenceSecretKey(frame.name) ||
		!isContextSecretValue(frame.name, decoded) || len(s.findings) >= maxStructuredFindings {
		return true
	}
	raw := bytes.Clone(s.data[start:end])
	s.findings = append(s.findings, detector.RawFinding{
		DetectorID: s.detector.ID(), Raw: raw, Redacted: detector.RedactBytes(raw),
		ExtraData: map[string]string{
			"key_name": frame.name, "key_path": joinJSONPath(frame.path), "config_format": "xml",
		},
		ByteStart: start, ByteEnd: end,
	})
	return true
}

func parseXMLAttributeSpans(raw []byte, base int, decoded []xml.Attr) ([]xmlAttributeSpan, bool) {
	if len(raw) < 3 || raw[0] != '<' {
		return nil, false
	}
	i := xmlNameEnd(raw, 1)
	spans := make([]xmlAttributeSpan, 0, len(decoded))
	for i < len(raw) {
		i = skipXMLSpace(raw, i)
		if i >= len(raw) || raw[i] == '>' || raw[i] == '/' {
			break
		}
		if len(spans) >= len(decoded) {
			return nil, false
		}
		span, next, ok := parseXMLAttributeSpan(raw, base, i, decoded[len(spans)])
		if !ok {
			return nil, false
		}
		spans = append(spans, span)
		i = next
	}
	return spans, len(spans) == len(decoded)
}

func xmlNameEnd(raw []byte, start int) int {
	for start < len(raw) && !isXMLSpace(raw[start]) && raw[start] != '>' && raw[start] != '/' {
		start++
	}
	return start
}

func skipXMLSpace(raw []byte, start int) int {
	for start < len(raw) && isXMLSpace(raw[start]) {
		start++
	}
	return start
}

func parseXMLAttributeSpan(raw []byte, base, start int, decoded xml.Attr) (xmlAttributeSpan, int, bool) {
	nameEnd := start
	for nameEnd < len(raw) && !isXMLSpace(raw[nameEnd]) && raw[nameEnd] != '=' && raw[nameEnd] != '>' && raw[nameEnd] != '/' {
		nameEnd++
	}
	if nameEnd == start {
		return xmlAttributeSpan{}, 0, false
	}
	valueStart := skipXMLSpace(raw, nameEnd)
	if valueStart >= len(raw) || raw[valueStart] != '=' {
		return xmlAttributeSpan{}, 0, false
	}
	valueStart = skipXMLSpace(raw, valueStart+1)
	if valueStart >= len(raw) || (raw[valueStart] != '\'' && raw[valueStart] != '"') {
		return xmlAttributeSpan{}, 0, false
	}
	quote := raw[valueStart]
	valueStart++
	closingOffset := bytes.IndexByte(raw[valueStart:], quote)
	if closingOffset < 0 {
		return xmlAttributeSpan{}, 0, false
	}
	valueEnd := valueStart + closingOffset
	return xmlAttributeSpan{
		name: decoded.Name.Local, value: decoded.Value,
		valueStart: base + valueStart, valueEnd: base + valueEnd,
	}, valueEnd + 1, true
}

func appendXMLAttributeFindings(
	d *StructuredConfigDetector,
	findings []detector.RawFinding,
	data []byte,
	path []string,
	attributes []xmlAttributeSpan,
) []detector.RawFinding {
	appendFinding := func(key string, span xmlAttributeSpan, keyPath []string) {
		if len(findings) >= maxStructuredFindings || !isHighConfidenceSecretKey(key) ||
			!isContextSecretValue(key, span.value) || span.valueStart >= span.valueEnd {
			return
		}
		raw := bytes.Clone(data[span.valueStart:span.valueEnd])
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(), Raw: raw, Redacted: detector.RedactBytes(raw),
			ExtraData: map[string]string{
				"key_name": key, "key_path": joinJSONPath(keyPath), "config_format": "xml",
			},
			ByteStart: span.valueStart, ByteEnd: span.valueEnd,
		})
	}

	for _, attribute := range attributes {
		if isHighConfidenceSecretKey(attribute.name) {
			appendFinding(attribute.name, attribute, appendJSONPath(path, "@"+attribute.name))
		}
	}
	var semanticKey string
	var valueAttribute *xmlAttributeSpan
	for i := range attributes {
		switch strings.ToLower(attributes[i].name) {
		case "key", "name":
			if isHighConfidenceSecretKey(attributes[i].value) {
				semanticKey = attributes[i].value
			}
		case "value", "secret":
			valueAttribute = &attributes[i]
		}
	}
	if semanticKey != "" && valueAttribute != nil {
		appendFinding(semanticKey, *valueAttribute, appendJSONPath(path, semanticKey))
	}
	return findings
}

func isXMLSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func trimSpaceBounds(data []byte, start, end int) (int, int) {
	for start < end && isASCIISpace(data[start]) {
		start++
	}
	for end > start && isASCIISpace(data[end-1]) {
		end--
	}
	return start, end
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

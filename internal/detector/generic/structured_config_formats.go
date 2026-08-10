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
)

const maxStructuredInputBytes = 4 * 1024 * 1024

type lineConfigFormat string

const (
	formatDotenv lineConfigFormat = "dotenv"
	formatTOML   lineConfigFormat = "toml"
	formatYAML   lineConfigFormat = "yaml"
)

type lineAssignment struct {
	key                  string
	value                string
	valueStart, valueEnd int
	indent               int
	hasValue             bool
}

type yamlSignal struct {
	indent   int
	hasValue bool
}

func (d *StructuredConfigDetector) scanLineConfig(ctx context.Context, data []byte) []detector.RawFinding {
	if len(data) > maxStructuredInputBytes || !utf8.Valid(data) {
		return nil
	}
	format, confident := detectLineConfigFormat(data)
	if !confident {
		return nil
	}
	findings := make([]detector.RawFinding, 0, 4)
	var yamlPath []yamlPathComponent
	var tomlPath []string

	for offset, lineNo := 0, 0; offset < len(data); lineNo++ {
		if lineNo&255 == 0 && ctx.Err() != nil {
			return nil
		}
		lineEnd := bytes.IndexByte(data[offset:], '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		} else {
			lineEnd += offset
		}
		line := data[offset:lineEnd]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		if format == formatTOML {
			if section, ok := parseTOMLSection(line); ok {
				tomlPath = section
				offset = nextLineOffset(lineEnd, len(data))
				continue
			}
		}

		assignment, ok := parseLineAssignment(line, offset, format)
		if !ok {
			offset = nextLineOffset(lineEnd, len(data))
			continue
		}

		var path []string
		switch format {
		case formatYAML:
			for len(yamlPath) > 0 && yamlPath[len(yamlPath)-1].indent >= assignment.indent {
				yamlPath = yamlPath[:len(yamlPath)-1]
			}
			path = yamlComponents(yamlPath)
			if !assignment.hasValue {
				yamlPath = append(yamlPath, yamlPathComponent{indent: assignment.indent, key: assignment.key})
				offset = nextLineOffset(lineEnd, len(data))
				continue
			}
		case formatTOML:
			path = tomlPath
		}

		if assignment.hasValue && isHighConfidenceSecretKey(assignment.key) &&
			isContextSecretValue(assignment.key, assignment.value) && len(findings) < maxStructuredFindings {
			keyPath := joinJSONPath(appendJSONPath(path, assignment.key))
			raw := bytes.Clone(data[assignment.valueStart:assignment.valueEnd])
			findings = append(findings, detector.RawFinding{
				DetectorID: d.ID(),
				Raw:        raw,
				Redacted:   detector.RedactBytes(raw),
				ExtraData: map[string]string{
					"key_name":      assignment.key,
					"key_path":      keyPath,
					"config_format": string(format),
				},
				ByteStart: assignment.valueStart,
				ByteEnd:   assignment.valueEnd,
			})
		}
		offset = nextLineOffset(lineEnd, len(data))
	}
	return findings
}

func detectLineConfigFormat(data []byte) (lineConfigFormat, bool) {
	yamlSignals := make([]yamlSignal, 0, 4)
	hasYAMLDocumentMarker := false
	dotenvAssignments := 0
	dotenvInvalid := false
	for offset := 0; offset < len(data); {
		lineEnd := bytes.IndexByte(data[offset:], '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		} else {
			lineEnd += offset
		}
		line := bytes.TrimSpace(data[offset:lineEnd])
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) || bytes.HasPrefix(line, []byte("//")) {
			offset = nextLineOffset(lineEnd, len(data))
			continue
		}
		if lineAssignment, ok := parseTOMLSection(line); ok && len(lineAssignment) > 0 {
			return formatTOML, true
		}
		if bytes.Equal(line, []byte("---")) {
			hasYAMLDocumentMarker = true
			offset = nextLineOffset(lineEnd, len(data))
			continue
		}
		if signal, ok := yamlMappingSignal(data[offset:lineEnd]); ok {
			yamlSignals = append(yamlSignals, signal)
			dotenvInvalid = true
		} else if isDotenvAssignment(line) {
			dotenvAssignments++
		} else {
			dotenvInvalid = true
		}
		offset = nextLineOffset(lineEnd, len(data))
	}
	if (hasYAMLDocumentMarker && len(yamlSignals) > 0) || hasNestedYAMLSignals(yamlSignals) {
		return formatYAML, true
	}
	if dotenvAssignments > 0 && !dotenvInvalid && len(yamlSignals) == 0 {
		return formatDotenv, true
	}
	return "", false
}

func yamlMappingSignal(line []byte) (yamlSignal, bool) {
	trimmed := bytes.TrimLeft(line, " \t")
	indent := visualIndent(line[:len(line)-len(trimmed)])
	index := bytes.IndexByte(trimmed, ':')
	if index <= 0 || !isPlainConfigKey(bytes.TrimSpace(trimmed[:index])) {
		return yamlSignal{}, false
	}
	return yamlSignal{indent: indent, hasValue: len(bytes.TrimSpace(trimmed[index+1:])) > 0}, true
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
	trimmed := bytes.TrimLeft(line, " \t")
	indentBytes := len(line) - len(trimmed)
	if len(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';' || bytes.HasPrefix(trimmed, []byte("//")) {
		return lineAssignment{}, false
	}
	if format == formatDotenv && bytes.HasPrefix(trimmed, []byte("export ")) {
		rest := trimmed[len("export "):]
		withoutSpacing := bytes.TrimLeft(rest, " \t")
		indentBytes += len("export ") + len(rest) - len(withoutSpacing)
		trimmed = withoutSpacing
	}

	delimiter := byte('=')
	if format == formatYAML {
		delimiter = ':'
	}
	index := bytes.IndexByte(trimmed, delimiter)
	if index <= 0 {
		return lineAssignment{}, false
	}
	keyBytes := bytes.TrimSpace(trimmed[:index])
	if !isPlainConfigKey(keyBytes) {
		return lineAssignment{}, false
	}
	key := string(keyBytes)
	valueBase := base + indentBytes + index + 1
	valueBytes := trimmed[index+1:]
	if len(bytes.TrimSpace(valueBytes)) == 0 {
		return lineAssignment{key: key, indent: visualIndent(line[:len(line)-len(trimmed)])}, true
	}
	value, start, end, ok := parseLineScalar(valueBytes, valueBase, format)
	if !ok {
		return lineAssignment{}, false
	}
	return lineAssignment{
		key:        key,
		value:      value,
		valueStart: start,
		valueEnd:   end,
		indent:     visualIndent(line[:len(line)-len(trimmed)]),
		hasValue:   true,
	}, true
}

func parseLineScalar(value []byte, base int, format lineConfigFormat) (string, int, int, bool) {
	left := len(value) - len(bytes.TrimLeft(value, " \t"))
	value = value[left:]
	base += left
	if len(value) == 0 || value[0] == '|' || value[0] == '>' || value[0] == '[' || value[0] == '{' {
		return "", 0, 0, false
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		end := findClosingQuote(value, quote)
		if end <= 0 || !onlyWhitespaceOrComment(value[end+1:]) {
			return "", 0, 0, false
		}
		raw := value[1:end]
		decoded := string(raw)
		if quote == '"' {
			unquoted, err := strconv.Unquote(string(value[:end+1]))
			if err != nil {
				return "", 0, 0, false
			}
			decoded = unquoted
		} else if format == formatTOML {
			decoded = strings.ReplaceAll(decoded, "''", "'")
		}
		return decoded, base + 1, base + end, true
	}

	end := len(value)
	for i := 1; i < len(value); i++ {
		if value[i] == '#' && (value[i-1] == ' ' || value[i-1] == '\t') {
			end = i
			break
		}
	}
	raw := bytes.TrimRight(value[:end], " \t\r")
	if len(raw) == 0 || format == formatTOML {
		return "", 0, 0, false
	}
	return string(raw), base, base + len(raw), true
}

func findClosingQuote(value []byte, quote byte) int {
	for i := 1; i < len(value); i++ {
		if value[i] != quote {
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
	text         strings.Builder
	hasChild     bool
	validText    bool
}

func (d *StructuredConfigDetector) scanXML(ctx context.Context, data []byte) []detector.RawFinding {
	if len(data) > maxStructuredInputBytes || !utf8.Valid(data) {
		return nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	stack := make([]xmlFrame, 0, 8)
	findings := make([]detector.RawFinding, 0, 4)
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
		switch value := token.(type) {
		case xml.StartElement:
			if len(stack) >= maxStructuredDepth {
				return nil
			}
			path := []string(nil)
			if len(stack) > 0 {
				stack[len(stack)-1].hasChild = true
				path = append(path, stack[len(stack)-1].path...)
			}
			path = append(path, value.Name.Local)
			stack = append(stack, xmlFrame{
				name: value.Name.Local, path: path,
				contentStart: int(decoder.InputOffset()), textStart: -1, validText: true,
			})
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			frame := &stack[len(stack)-1]
			start := tokenStart
			end := int(decoder.InputOffset())
			if frame.textStart < 0 {
				frame.textStart = start
			}
			frame.textEnd = end
			frame.text.Write([]byte(value))
		case xml.Comment, xml.Directive, xml.ProcInst:
			if len(stack) > 0 {
				stack[len(stack)-1].validText = false
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].name != value.Name.Local {
				return nil
			}
			frame := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if frame.hasChild || !frame.validText || frame.textStart < frame.contentStart {
				continue
			}
			decoded := strings.TrimSpace(frame.text.String())
			start, end := trimSpaceBounds(data, frame.textStart, frame.textEnd)
			if start >= end || !isHighConfidenceSecretKey(frame.name) ||
				!isContextSecretValue(frame.name, decoded) || len(findings) >= maxStructuredFindings {
				continue
			}
			raw := bytes.Clone(data[start:end])
			findings = append(findings, detector.RawFinding{
				DetectorID: d.ID(), Raw: raw, Redacted: detector.RedactBytes(raw),
				ExtraData: map[string]string{
					"key_name": frame.name, "key_path": joinJSONPath(frame.path), "config_format": "xml",
				},
				ByteStart: start, ByteEnd: end,
			})
		}
	}
	if len(stack) != 0 {
		return nil
	}
	return findings
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

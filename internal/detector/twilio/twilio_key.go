// Package twilio provides a detector for paired Twilio API Key credentials.
package twilio

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	// An SK value is an API Key SID: a public identifier, not a secret. It is
	// used only as companion context when it is assigned to an API Key SID role.
	twilioKeySIDAssignmentPattern     = regexp.MustCompile(`(?i)(?:^|[^0-9A-Za-z_])(?:(?:[a-z0-9]+[._-]+)*twilio[._-]*|x[._-]*)?api[._-]*(?:key[._-]*)?sid["']?\s*[:=]\s*["']?(SK[0-9a-f]{32})(?:["']|[ \t\r\n,;}#]|$)`)
	twilioAccountSIDAssignmentPattern = regexp.MustCompile(`(?i)(?:^|[^0-9A-Za-z_])(?:(?:[a-z0-9]+[._-]+)*twilio[._-]*)?account[._-]*sid["']?\s*[:=]\s*["']?(AC[0-9a-f]{32})(?:["']|[ \t\r\n,;}#]|$)`)

	// Twilio documents API Key Secrets as opaque values and does not promise a
	// fixed length or alphabet. These alternatives preserve an exact value span
	// for double-quoted, single-quoted, and bounded unquoted assignments.
	twilioAPISecretAssignmentPattern = regexp.MustCompile(`(?i)(?:^|[^0-9A-Za-z_])(?:(?:[a-z0-9]+[._-]+)*twilio[._-]*|x[._-]*)?api[._-]*(?:key[._-]*)?secret["']?\s*[:=]\s*(?:"([^"\r\n]{1,512})"|'([^'\r\n]{1,512})'|([^"' \t\r\n,;}#]{1,512})(?:[ \t\r\n,;}#]|$))`)

	logicalBlockSeparatorPattern = regexp.MustCompile(`(?:\r?\n[ \t]*\r?\n|\r?\n[ \t]*\[[^\r\n]+\][ \t]*(?:\r?\n|$))`)
)

// companionProximityWindow bounds how far a non-secret SID may sit from the
// secret assignment to be treated as the same credential pair.
const companionProximityWindow = 512

// Detector detects Twilio API Key Secrets only when paired with a nearby API
// Key SID. A bare SK SID is intentionally not a finding because it is not
// confidential and cannot authenticate to Twilio.
type Detector struct{}

// ID returns the stable detector identifier.
func (d *Detector) ID() string { return "twilio-api-key" }

// Description returns a human-readable description.
func (d *Detector) Description() string { return "Twilio API Key Secret" }

// Keywords returns the invariant role component shared by every supported
// secret assignment. The matcher lowercases chunks before keyword selection,
// so this skips unrelated files without losing casing or separator variants.
func (d *Detector) Keywords() []string { return []string{"secret"} }

// Severity returns the default severity level for a leaked API Key Secret.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// AuthoritativeOnOverlap lets the engine prefer this provider-specific paired
// finding over a structured-config fallback for the same secret bytes.
func (d *Detector) AuthoritativeOnOverlap() bool { return true }

// PlaygroundPatternContract prevents the site generator from publishing the
// SID and secret-assignment regexes as independent OR triggers.
func (d *Detector) PlaygroundPatternContract() detector.PlaygroundPatternContract {
	return detector.PlaygroundPatternContract{
		Primary:            []*regexp.Regexp{twilioAPISecretAssignmentPattern},
		RequiredNearby:     []*regexp.Regexp{twilioKeySIDAssignmentPattern},
		ProximityBytes:     companionProximityWindow,
		SameLogicalBlock:   true,
		RejectPlaceholders: true,
		OneToOne:           true,
	}
}

var _ detector.PlaygroundCorrelated = (*Detector)(nil)

// Scan reports the secret value as Raw and carries only non-secret SIDs in
// ExtraData. It never stores the API Key Secret in ExtraData.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	secrets := assignmentMatches(twilioAPISecretAssignmentPattern, data)
	if len(secrets) == 0 {
		return nil
	}

	keySIDs := assignmentMatches(twilioKeySIDAssignmentPattern, data)
	if len(keySIDs) == 0 {
		return nil
	}
	accountSIDs := assignmentMatches(twilioAccountSIDAssignmentPattern, data)

	findings := make([]detector.RawFinding, 0, len(secrets))
	usedKeySIDs := make([]bool, len(keySIDs))
	for _, secretMatch := range secrets {
		secret := data[secretMatch.valueStart:secretMatch.valueEnd]
		if isNonSecretValue(string(secret)) {
			continue
		}

		keyIndex, ambiguous := nearestUnusedCompanionMatch(data, secretMatch, keySIDs, usedKeySIDs)
		if keyIndex < 0 {
			continue
		}
		usedKeySIDs[keyIndex] = true
		keyMatch := keySIDs[keyIndex]

		extra := map[string]string{
			"api_key_sid": string(data[keyMatch.valueStart:keyMatch.valueEnd]),
		}
		if ambiguous {
			extra["pairing_ambiguous"] = "true"
		}
		if accountIndex := nearestCompanion(data, keyMatch, accountSIDs); accountIndex >= 0 {
			accountMatch := accountSIDs[accountIndex]
			extra["account_sid"] = string(data[accountMatch.valueStart:accountMatch.valueEnd])
		}
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(secret),
			Redacted:   detector.RedactBytes(secret),
			ExtraData:  extra,
			ByteStart:  secretMatch.valueStart,
			ByteEnd:    secretMatch.valueEnd,
		})
	}
	return findings
}

type assignmentMatch struct {
	wholeStart int
	wholeEnd   int
	valueStart int
	valueEnd   int
}

// assignmentMatches returns exact full-assignment and captured-value spans.
// Patterns may contain alternatives, so the first participating capture is
// used as the value.
func assignmentMatches(pattern *regexp.Regexp, data []byte) []assignmentMatch {
	indices := pattern.FindAllSubmatchIndex(data, -1)
	matches := make([]assignmentMatch, 0, len(indices))
	for _, index := range indices {
		if len(index) < 4 {
			continue
		}
		valueStart, valueEnd := -1, -1
		for i := 2; i+1 < len(index); i += 2 {
			if index[i] >= 0 && index[i+1] >= index[i] {
				valueStart, valueEnd = index[i], index[i+1]
				break
			}
		}
		if valueStart < 0 || valueEnd <= valueStart {
			continue
		}
		if valueEnd < len(data) && (data[valueEnd] == '"' || data[valueEnd] == '\'') && escapedAt(data, valueEnd) {
			// Do not treat an escaped quote inside a JSON, shell, or language
			// string as the assignment terminator and report a truncated secret.
			continue
		}
		wholeStart := index[0]
		if wholeStart < len(data) && !isASCIIAlphaNumeric(data[wholeStart]) {
			_, size := utf8.DecodeRune(data[wholeStart:])
			wholeStart += size
		}
		matches = append(matches, assignmentMatch{
			wholeStart: wholeStart,
			// End correlation at the value, excluding a closing quote or a
			// delimiter consumed only to prove the lexical boundary.
			wholeEnd:   valueEnd,
			valueStart: valueStart,
			valueEnd:   valueEnd,
		})
	}
	return matches
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9'
}

func escapedAt(data []byte, index int) bool {
	backslashes := 0
	for i := index - 1; i >= 0 && data[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func nearestUnusedCompanion(data []byte, target assignmentMatch, candidates []assignmentMatch, used []bool) int {
	best, _ := nearestUnusedCompanionMatch(data, target, candidates, used)
	return best
}

func nearestUnusedCompanionMatch(data []byte, target assignmentMatch, candidates []assignmentMatch, used []bool) (int, bool) {
	best := -1
	bestDist := -1
	ambiguous := false
	for i, candidate := range candidates {
		if used[i] {
			continue
		}
		dist := rangeGap(target, candidate)
		if dist > companionProximityWindow || !sameLogicalBlock(data, target, candidate) {
			continue
		}
		if bestDist == -1 || dist < bestDist {
			bestDist = dist
			best = i
			ambiguous = false
		} else if dist == bestDist {
			ambiguous = true
			// Consecutive SID/SECRET pairs put a secret equidistant from the
			// preceding credential and the next SID. Prefer the preceding SID;
			// suppressing the finding would hide a real credential.
			if candidate.wholeEnd <= target.wholeStart &&
				(best < 0 || candidates[best].wholeEnd > target.wholeStart) {
				best = i
			}
		}
	}
	return best, ambiguous
}

func nearestCompanion(data []byte, target assignmentMatch, candidates []assignmentMatch) int {
	return nearestUnusedCompanion(data, target, candidates, make([]bool, len(candidates)))
}

func sameLogicalBlock(data []byte, a, b assignmentMatch) bool {
	start, end := a.wholeEnd, b.wholeStart
	if b.wholeEnd <= a.wholeStart {
		start, end = b.wholeEnd, a.wholeStart
	}
	if start > end || start < 0 || end > len(data) {
		return false
	}
	between := data[start:end]
	return !logicalBlockSeparatorPattern.Match(between) && !bytes.ContainsAny(between, "{}")
}

// rangeGap returns the byte distance between two non-overlapping ranges.
func rangeGap(a, b assignmentMatch) int {
	switch {
	case a.wholeEnd <= b.wholeStart:
		return b.wholeStart - a.wholeEnd
	case b.wholeEnd <= a.wholeStart:
		return a.wholeStart - b.wholeEnd
	default:
		return 0
	}
}

func isNonSecretValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	placeholders := map[string]struct{}{
		"change-me": {}, "change_me": {}, "changeme": {}, "dummy": {},
		"example": {}, "example-secret": {}, "example_secret": {}, "fixme": {},
		"foobar": {}, "not-a-real-secret": {}, "not_a_real_secret": {},
		"placeholder": {}, "redacted": {}, "replace-me": {}, "replace_me": {},
		"secret": {}, "string": {}, "test": {}, "todo": {},
		"api-key-secret": {}, "api_key_secret": {},
		"twilio-api-key-secret": {}, "twilio_api_key_secret": {}, "twilioapikeysecret": {},
		"your-api-key-secret": {}, "your_api_key_secret": {},
		"your-twilio-api-key-secret": {}, "your_twilio_api_key_secret": {}, "xxxxxxxx": {},
	}
	if _, ok := placeholders[lower]; ok {
		return true
	}
	for _, prefix := range []string{
		"${", "$", "{{", "%", "<", "vault://", "op://", "secret://",
		"file://", "/run/secrets/", "@microsoft.keyvault",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if len(lower) >= 4 && strings.Trim(lower, "x*0-") == "" {
		return true
	}
	return false
}

func init() {
	detector.Register(&Detector{})
}

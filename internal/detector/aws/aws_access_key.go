// Package aws provides AWS-related secret detectors.
package aws

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var accessKeyIDPattern = regexp.MustCompile(`(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`)

// awsSecretKeyedPattern matches a Secret Access Key that follows an explicit
// aws_secret_access_key assignment (highest confidence pairing).
var awsSecretKeyedPattern = regexp.MustCompile(`(?i)aws_secret_access_key["']?\s*[=:]\s*["']?([A-Za-z0-9/+]{40})`)

// awsSecretBarePattern matches a bare 40-character Secret Access Key candidate
// that is bounded on both sides (i.e. not part of a longer token). The leading
// and trailing boundary groups keep it from carving a 40-char slice out of a
// longer base64-like blob.
var awsSecretBarePattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`)

// secretPairingRadius is the number of bytes searched before and after an
// Access Key ID match when looking for a co-located Secret Access Key. Access
// key IDs and their secret counterparts are almost always defined together
// (e.g. an AWS credentials file or config block), so a bounded window keeps the
// pairing reliable without correlating unrelated secrets across a large file.
const secretPairingRadius = 512

// exampleAccessKeys is the set of AWS's own canonical, permanently-invalid
// documentation placeholder Access Key IDs. AWS uses these throughout its docs
// and SDK examples, so treating them as findings produces a Critical false
// positive on essentially every repository that contains AWS example code.
var exampleAccessKeys = map[string]struct{}{
	"AKIAIOSFODNN7EXAMPLE": {},
	"ASIAIOSFODNN7EXAMPLE": {},
	"ABIAIOSFODNN7EXAMPLE": {},
	"ACCAIOSFODNN7EXAMPLE": {},
}

// AccessKeyID detects AWS Access Key IDs.
type AccessKeyID struct{}

// ID returns the unique identifier of the AWS Access Key ID detector.
func (d *AccessKeyID) ID() string { return "aws-access-key-id" }

// Description returns a human-readable description of the detector.
func (d *AccessKeyID) Description() string { return "AWS Access Key ID" }

// Keywords returns the Aho-Corasick pre-filter keywords for detection.
func (d *AccessKeyID) Keywords() []string { return []string{"AKIA", "ABIA", "ACCA", "ASIA"} }

// Severity returns the default severity for AWS Access Key ID findings.
func (d *AccessKeyID) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for AWS Access Key ID patterns.
//
// When a co-located AWS Secret Access Key is found within a bounded window of
// an Access Key ID, it is attached to the finding via RawV2 so the AWS verifier
// can perform a live STS check. RawV2 is consumed only in-memory by the
// verifier and is never serialized into output, so the secret key is never
// exposed in a report.
func (d *AccessKeyID) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := accessKeyIDPattern.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, loc := range matches {
		start, end := loc[0], loc[1]

		// Reject truncated captures: a valid key must not be immediately
		// adjacent to another alphanumeric character on either side, which
		// would mean the match was carved out of a longer identifier.
		if !isBoundedMatch(data, start, end) {
			continue
		}

		match := data[start:end]

		// Skip AWS's own well-known documentation placeholder keys.
		if _, ok := exampleAccessKeys[string(match)]; ok {
			continue
		}

		f := detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactBytes(match),
		}

		if secret := findSecretKey(data, start, end); secret != nil {
			f.RawV2 = secret
		}

		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

// isBoundedMatch reports whether the [start,end) match is not immediately
// preceded or followed by another alphanumeric character. Go's RE2 has no
// lookaround, so this fixed-length boundary check is done outside the regex to
// avoid emitting a truncated key sliced out of a longer adjacent token.
func isBoundedMatch(data []byte, start, end int) bool {
	if start > 0 && isAlphaNum(data[start-1]) {
		return false
	}
	if end < len(data) && isAlphaNum(data[end]) {
		return false
	}
	return true
}

func isAlphaNum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// findSecretKey looks for a co-located AWS Secret Access Key within a bounded
// window around the Access Key ID match at [keyStart,keyEnd). It prefers an
// explicit aws_secret_access_key assignment and falls back to a bounded bare
// 40-character candidate. The returned slice is a fresh copy so it never aliases
// the caller's buffer. Returns nil when no plausible secret is co-located.
func findSecretKey(data []byte, keyStart, keyEnd int) []byte {
	winStart := keyStart - secretPairingRadius
	if winStart < 0 {
		winStart = 0
	}
	winEnd := keyEnd + secretPairingRadius
	if winEnd > len(data) {
		winEnd = len(data)
	}
	window := data[winStart:winEnd]

	if m := awsSecretKeyedPattern.FindSubmatch(window); m != nil {
		return bytes.Clone(m[1])
	}
	// awsSecretBarePattern's ^/$ alternatives anchor to the WINDOW, not to data.
	// A window edge that falls inside a longer base64-like token would otherwise
	// satisfy them and carve a spurious 40-character "secret" out of the middle
	// of that token. Map the capture back to absolute offsets and re-check the
	// real neighbours in data against the pattern's own character class.
	if locs := awsSecretBarePattern.FindSubmatchIndex(window); locs != nil {
		start, end := winStart+locs[2], winStart+locs[3]
		if isSecretBounded(data, start, end) {
			return bytes.Clone(data[start:end])
		}
	}
	return nil
}

// isSecretBounded reports whether data[start:end] is delimited by bytes outside
// the Secret Access Key character class, i.e. the match is a standalone token
// rather than a slice of a longer base64-like string.
func isSecretBounded(data []byte, start, end int) bool {
	if start > 0 && isSecretKeyByte(data[start-1]) {
		return false
	}
	if end < len(data) && isSecretKeyByte(data[end]) {
		return false
	}
	return true
}

// isSecretKeyByte matches awsSecretBarePattern's [A-Za-z0-9/+] class.
func isSecretKeyByte(b byte) bool {
	return isAlphaNum(b) || b == '/' || b == '+'
}

func init() {
	detector.Register(&AccessKeyID{})
}

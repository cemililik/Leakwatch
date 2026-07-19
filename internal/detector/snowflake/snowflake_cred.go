// Package snowflake provides a Snowflake Connection Credentials secret detector.
package snowflake

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// snowflakeMask is the placeholder written in place of a redacted password value.
const snowflakeMask = "****"

// snowflakeCredPattern matches a Snowflake connection string that carries an
// embedded password. The prefix wildcard is length-bounded (was unbounded) so a
// single match cannot run away across an entire compact line; any password-family
// parameter caught inside the bounded span is masked by redactSnowflake.
var snowflakeCredPattern = regexp.MustCompile(`snowflakecomputing\.com[^\s]{0,512}(?:password|pwd|PWD|PASSWORD)\s*=\s*([^&\s'"]+)`)

// snowflakePwdRedactPattern matches every password/pwd parameter (any case,
// any whitespace around "=") so redaction masks the value using the exact same
// whitespace semantics as the detection regex above. Masking is applied to all
// occurrences so an earlier decoy credential cannot survive in cleartext.
var snowflakePwdRedactPattern = regexp.MustCompile(`(?i)(password|pwd)(\s*=\s*)[^&\s'"]+`)

// Detector detects Snowflake Connection Credentials with embedded passwords.
type Detector struct{}

// ID returns the unique identifier of the Snowflake Credentials detector.
func (d *Detector) ID() string { return "snowflake-credentials" }

// Description returns a human-readable description of the Snowflake Credentials detector.
func (d *Detector) Description() string { return "Snowflake Connection Credentials" }

// Keywords returns the Aho-Corasick pre-filter keywords for Snowflake Credentials detection.
func (d *Detector) Keywords() []string {
	return []string{"snowflakecomputing"}
}

// Severity returns the default severity level for Snowflake Credentials findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Snowflake connection strings containing passwords.
// The password value is extracted from the match and redacted in the finding output.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := snowflakeCredPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		passwordValue := groups[1]

		// NOTE: the raw password is intentionally NOT placed into ExtraData.
		// ExtraData is serialized into default (non --show-raw) output, so it
		// must never carry secret material. The plaintext value is exposed only
		// through Raw, which is gated behind the --show-raw opt-in downstream.
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        passwordValue,
			RawV2:      fullMatch,
			Redacted:   redactSnowflake(string(fullMatch)),
		})
	}
	return findings
}

// redactSnowflake masks every password/pwd value in the matched string.
//
// It uses the same whitespace-tolerant semantics as the detection regex, so any
// input the detector accepts (including tab, newline, or multi-space around
// "=") is redacted. The function fails safe: if no password parameter can be
// located it returns a full mask rather than the input verbatim, so redactor
// drift can never leak a secret into the (always-emitted) Redacted field.
func redactSnowflake(match string) string {
	redacted := snowflakePwdRedactPattern.ReplaceAllString(match, "${1}${2}"+snowflakeMask)
	if redacted == match {
		return snowflakeMask
	}
	return redacted
}

func init() {
	detector.Register(&Detector{})
}

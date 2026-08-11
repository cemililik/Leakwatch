// Package finding defines the Leakwatch finding model.
// This package is public and can be consumed by external tools such as CI plugins.
package finding

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity represents the finding severity level.
type Severity int

const (
	SeverityLow      Severity = iota // Low
	SeverityMedium                   // Medium
	SeverityHigh                     // High
	SeverityCritical                 // Critical
)

// severityToString maps Severity values to strings.
var severityToString = map[Severity]string{
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// stringToSeverity maps strings to Severity values.
var stringToSeverity = map[string]Severity{
	"low":      SeverityLow,
	"medium":   SeverityMedium,
	"high":     SeverityHigh,
	"critical": SeverityCritical,
}

// String returns the human-readable representation of Severity.
func (s Severity) String() string {
	if str, ok := severityToString[s]; ok {
		return str
	}
	return "unknown"
}

// ParseSeverity converts a severity name to its Severity value. Matching is
// case-sensitive against the four canonical names ("low", "medium", "high",
// "critical"). The boolean is false when s is not one of them, so callers can
// decide their own fallback or reject the value explicitly instead of silently
// downgrading an unrecognized string. It is the single source of truth shared by
// the CLI (--min-severity) and custom-rule severity parsing.
func ParseSeverity(s string) (Severity, bool) {
	sev, ok := stringToSeverity[s]
	return sev, ok
}

// MarshalJSON serializes Severity as a JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	str := s.String()
	if str == "unknown" {
		return nil, fmt.Errorf("invalid Severity value: %d", int(s))
	}
	return json.Marshal(str)
}

// UnmarshalJSON parses a Severity value from a JSON string.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal Severity JSON: %w", err)
	}
	val, ok := stringToSeverity[str]
	if !ok {
		return fmt.Errorf("invalid Severity value: %q", str)
	}
	*s = val
	return nil
}

// VerificationStatus represents the verification state.
type VerificationStatus int

const (
	StatusUnverified       VerificationStatus = iota // Not verified
	StatusVerifiedActive                             // Verified: secret is active
	StatusVerifiedInactive                           // Verified: secret is inactive
	StatusVerifyError                                // Verification error
)

// verificationStatusToString maps VerificationStatus values to strings.
var verificationStatusToString = map[VerificationStatus]string{
	StatusUnverified:       "unverified",
	StatusVerifiedActive:   "verified_active",
	StatusVerifiedInactive: "verified_inactive",
	StatusVerifyError:      "verify_error",
}

// stringToVerificationStatus maps strings to VerificationStatus values.
var stringToVerificationStatus = map[string]VerificationStatus{
	"unverified":        StatusUnverified,
	"verified_active":   StatusVerifiedActive,
	"verified_inactive": StatusVerifiedInactive,
	"verify_error":      StatusVerifyError,
}

// String returns the human-readable representation of VerificationStatus.
func (v VerificationStatus) String() string {
	if str, ok := verificationStatusToString[v]; ok {
		return str
	}
	return "unknown"
}

// MarshalJSON serializes VerificationStatus as a JSON string.
func (v VerificationStatus) MarshalJSON() ([]byte, error) {
	str := v.String()
	if str == "unknown" {
		return nil, fmt.Errorf("invalid VerificationStatus value: %d", int(v))
	}
	return json.Marshal(str)
}

// UnmarshalJSON parses a VerificationStatus value from a JSON string.
func (v *VerificationStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("failed to unmarshal VerificationStatus JSON: %w", err)
	}
	val, ok := stringToVerificationStatus[str]
	if !ok {
		return fmt.Errorf("invalid VerificationStatus value: %q", str)
	}
	*v = val
	return nil
}

// VerificationResult represents the outcome of a verification attempt.
type VerificationResult struct {
	Status    VerificationStatus `json:"status"`
	Message   string             `json:"message,omitempty"`
	ExtraData map[string]string  `json:"extra_data,omitempty"`
}

// SourceMetadata describes the origin of a finding.
type SourceMetadata struct {
	SourceType string `json:"source_type"`

	// Git-specific fields
	Repository string    `json:"repository,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Author     string    `json:"author,omitempty"`
	Email      string    `json:"email,omitempty"`
	Date       time.Time `json:"date,omitempty"`
	Branch     string    `json:"branch,omitempty"`

	// File-specific fields
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`

	// Container-specific fields
	Image    string `json:"image,omitempty"`
	Layer    string `json:"layer,omitempty"`
	LayerIdx int    `json:"layer_idx,omitempty"`

	// Slack-specific fields
	Channel     string `json:"channel,omitempty"`
	ChannelName string `json:"channel_name,omitempty"`
	MessageUser string `json:"message_user,omitempty"`
	MessageTS   string `json:"message_ts,omitempty"`
	ThreadTS    string `json:"thread_ts,omitempty"`
}

// MarshalJSON serializes SourceMetadata, omitting Date when it holds the zero
// time. encoding/json's omitempty is a no-op on a time.Time struct value, so a
// non-git finding (which never sets Date) would otherwise serialize a bogus
// "date":"0001-01-01T00:00:00Z". A pointer shadow field lets omitempty apply.
func (m SourceMetadata) MarshalJSON() ([]byte, error) {
	type alias SourceMetadata
	shadow := struct {
		alias
		Date *time.Time `json:"date,omitempty"`
	}{alias: alias(m)}
	if !m.Date.IsZero() {
		shadow.Date = &m.Date
	}
	out, err := json.Marshal(shadow)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SourceMetadata JSON: %w", err)
	}
	return out, nil
}

// Remediation provides actionable guidance for rotating or revoking a detected secret.
type Remediation struct {
	Title      string   `json:"title"`
	Steps      []string `json:"steps"`
	DocURL     string   `json:"doc_url,omitempty"`
	ConsoleURL string   `json:"console_url,omitempty"`
	Urgency    string   `json:"urgency"`
	Checklist  []string `json:"checklist,omitempty"`
}

// Finding represents a fully enriched secret finding.
//
// The Raw field holds the unredacted secret. It carries a json:"-" tag so that
// the standard library NEVER serializes it: any external consumer that marshals
// a Finding cannot accidentally leak the secret. Output formatters that support
// an explicit opt-in (e.g. --show-raw) re-add the value via a dedicated wire
// type rather than relying on this struct's tags.
//
// ExtraData is treated with the same defense-in-depth as Raw: it also carries a
// json:"-" tag so a detector that mistakenly stashes secret material there can
// never leak it into the default (non --show-raw) output path. Formatters that
// support --show-raw re-add it through their own opt-in wire type.
type Finding struct {
	// ID is an opaque, deterministic identifier: a truncated SHA-256 rendered
	// as a lowercase hex string (32 hex characters, no dashes). It is NOT a
	// UUID; consumers must not validate it against a UUID format.
	ID         string   `json:"id"`
	DetectorID string   `json:"detector_id"`
	Severity   Severity `json:"severity"`
	Raw        string   `json:"-"`
	Redacted   string   `json:"redacted"`
	// SourceMetadata describes where the finding originated. Its custom
	// MarshalJSON omits a zero Date so non-git sources do not serialize a
	// bogus "0001-01-01T00:00:00Z".
	SourceMetadata SourceMetadata     `json:"source"`
	Verification   VerificationResult `json:"verification"`
	Remediation    *Remediation       `json:"remediation,omitempty"`
	DetectedAt     time.Time          `json:"detected_at,omitempty"`
	// Entropy is the Shannon entropy of the raw match. EntropyCalculated records
	// whether the value was actually computed, so a legitimate 0.0 is distinct
	// from "not computed" on the JSON wire without changing the long-standing
	// public Entropy float64 field. Call SetEntropy when constructing findings
	// outside the engine. For source compatibility, a non-zero Entropy value is
	// also serialized even when an older caller did not set EntropyCalculated.
	Entropy           float64 `json:"entropy,omitempty"`
	EntropyCalculated bool    `json:"-"`
	// ExtraData carries non-secret contextual metadata. It is json:"-" as a
	// defense-in-depth measure (see the type doc); it must never hold secret
	// material.
	ExtraData map[string]string `json:"-"`
}

// SetEntropy records a computed Shannon entropy value, including a legitimate
// zero. The explicit presence bit preserves the public float64 API while making
// the JSON representation nullable.
func (f *Finding) SetEntropy(value float64) {
	f.Entropy = value
	f.EntropyCalculated = true
}

// MarshalJSON omits zero DetectedAt and emits entropy only when it was
// calculated. A non-zero legacy value remains visible for source compatibility
// with callers written before EntropyCalculated existed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type alias Finding
	shadow := struct {
		alias
		DetectedAt *time.Time `json:"detected_at,omitempty"`
		Entropy    *float64   `json:"entropy,omitempty"`
	}{alias: alias(f)}
	if !f.DetectedAt.IsZero() {
		shadow.DetectedAt = &f.DetectedAt
	}
	if f.EntropyCalculated || f.Entropy != 0 {
		shadow.Entropy = &f.Entropy
	}
	out, err := json.Marshal(shadow)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Finding JSON: %w", err)
	}
	return out, nil
}

// UnmarshalJSON restores the entropy presence bit so a computed zero survives a
// JSON round trip. Missing timestamps and entropy values retain their Go zero
// values.
func (f *Finding) UnmarshalJSON(data []byte) error {
	type alias Finding
	var decoded alias
	shadow := struct {
		*alias
		DetectedAt *time.Time `json:"detected_at,omitempty"`
		Entropy    *float64   `json:"entropy,omitempty"`
	}{alias: &decoded}
	if err := json.Unmarshal(data, &shadow); err != nil {
		return fmt.Errorf("failed to unmarshal Finding JSON: %w", err)
	}
	*f = Finding(decoded)
	if shadow.DetectedAt != nil {
		f.DetectedAt = *shadow.DetectedAt
	}
	if shadow.Entropy != nil {
		f.SetEntropy(*shadow.Entropy)
	}
	return nil
}

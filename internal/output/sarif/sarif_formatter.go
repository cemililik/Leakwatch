// Package sarif provides a SARIF v2.1.0 output formatter for Leakwatch findings.
package sarif

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "Leakwatch"
	toolInfoURI  = "https://github.com/HodeTech/Leakwatch"
	// defaultToolVersion is used for tool.driver.version when Formatter.Version
	// is left unset (e.g. zero-value Formatter in tests or older callers). Real
	// scans should set Formatter.Version to the actual build version (see
	// Formatter.Version doc) so shipped SARIF never reports "dev".
	defaultToolVersion = "dev"
	rawPropertyKey     = "raw"
)

// sarifDocument represents the top-level SARIF v2.1.0 document.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun represents a single SARIF run.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool represents the tool metadata.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver represents the tool driver with rules.
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

// sarifRule represents a SARIF reporting descriptor (rule).
type sarifRule struct {
	ID               string             `json:"id"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	DefaultConfig    sarifDefaultConfig `json:"defaultConfiguration"`
	Help             *sarifHelp         `json:"help,omitempty"`
	HelpURI          string             `json:"helpUri,omitempty"`
}

// sarifHelp represents the help text for a SARIF rule.
type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// sarifDefaultConfig holds the default severity level for a rule.
type sarifDefaultConfig struct {
	Level string `json:"level"`
}

// sarifMessage represents a SARIF message with text.
type sarifMessage struct {
	Text string `json:"text"`
}

// sarifResult represents a single SARIF result.
type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

// sarifLocation represents a SARIF physical location.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation represents a file and region in a SARIF location.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

// sarifArtifactLocation represents the URI of a SARIF artifact.
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion represents a line region within a file.
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// Formatter outputs findings in SARIF v2.1.0 format.
type Formatter struct {
	// ShowRaw, when true, includes the unredacted secret value as a
	// "raw" entry under each result's properties bag. When false, no raw value
	// is emitted anywhere in the output.
	ShowRaw bool

	// Version is embedded verbatim as tool.driver.version. Callers should set
	// this to the real build version (the same value reported by `leakwatch
	// version`) so shipped SARIF documents are traceable to the Leakwatch
	// release that produced them. When left empty (e.g. a zero-value
	// Formatter), it falls back to defaultToolVersion ("dev") so existing
	// callers keep producing valid, non-empty output.
	Version string
}

// driverVersion returns f.Version, falling back to defaultToolVersion when
// unset.
func (f *Formatter) driverVersion() string {
	if f.Version == "" {
		return defaultToolVersion
	}
	return f.Version
}

// syntheticArtifactURI builds a stable, synthetic artifactLocation.uri for a
// finding whose source has no natural file path (currently: Slack). It
// returns "" for sources that either have a file path (the caller should use
// that instead) or that this function does not yet recognize, so a future
// non-file source without explicit support here still degrades to the prior
// location-less behavior rather than emitting a misleading URI.
//
// The URI is deterministic and derived only from non-secret identifying
// fields already present on SourceMetadata, so it is stable across repeated
// scans of the same message and never embeds the finding's redacted or raw
// match text.
func syntheticArtifactURI(m finding.SourceMetadata) string {
	switch m.SourceType {
	case "slack":
		// Strip a leading '#': it is the URI fragment delimiter, so
		// "slack://#general/..." would be parsed as an empty authority plus a
		// fragment by SARIF consumers.
		channel := strings.TrimPrefix(m.ChannelName, "#")
		if channel == "" {
			channel = strings.TrimPrefix(m.Channel, "#")
		}
		if channel == "" {
			channel = "unknown"
		}
		ts := m.MessageTS
		if ts == "" {
			ts = "unknown"
		}
		return fmt.Sprintf("slack://%s/%s", channel, ts)
	default:
		return ""
	}
}

// locationStableFingerprint returns a fingerprint that survives line moves so
// GitHub Code Scanning does not close and reopen an alert when surrounding code
// shifts. It deliberately excludes the line number (and uses NUL separators to
// avoid field-boundary collisions).
func locationStableFingerprint(fd finding.Finding) string {
	h := sha256.Sum256([]byte(fd.DetectorID + "\x00" + fd.Redacted + "\x00" + fd.SourceMetadata.FilePath))
	return fmt.Sprintf("%x", h[:16])
}

// severityToLevel maps finding severity to SARIF result level.
func severityToLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "error"
	case finding.SeverityHigh:
		return "warning"
	case finding.SeverityMedium, finding.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

// Format writes findings in SARIF v2.1.0 JSON to the given writer.
// When ShowRaw is true, each result carries the unredacted secret value under
// properties.raw; otherwise no raw value is emitted.
func (f *Formatter) Format(w io.Writer, findings []finding.Finding) error {
	// Build unique rules from detector IDs, preserving order of first appearance.
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, fd := range findings {
		if _, exists := ruleIndex[fd.DetectorID]; !exists {
			ruleIndex[fd.DetectorID] = len(rules)
			rule := sarifRule{
				ID:               fd.DetectorID,
				ShortDescription: sarifMessage{Text: fmt.Sprintf("Secret detected by %s", fd.DetectorID)},
				DefaultConfig:    sarifDefaultConfig{Level: severityToLevel(fd.Severity)},
			}

			// Populate help from remediation guidance when available.
			if fd.Remediation != nil && len(fd.Remediation.Steps) > 0 {
				rule.Help = &sarifHelp{
					Text: strings.Join(fd.Remediation.Steps, "\n"),
				}
				if fd.Remediation.DocURL != "" {
					rule.HelpURI = fd.Remediation.DocURL
				}
			}

			rules = append(rules, rule)
		}
	}

	// Build results.
	results := make([]sarifResult, 0, len(findings))
	for _, fd := range findings {
		msg := fmt.Sprintf("Secret found: %s", fd.Redacted)

		result := sarifResult{
			RuleID:    fd.DetectorID,
			RuleIndex: ruleIndex[fd.DetectorID],
			Level:     severityToLevel(fd.Severity),
			Message:   sarifMessage{Text: msg},
			// Location-independent fingerprint so GitHub Code Scanning tracks
			// the same alert when the secret moves to a different line. Derived
			// from detector + redacted value + file path only (NOT the line),
			// unlike Finding.ID which includes the line for in-tool dedup.
			PartialFingerprints: map[string]string{
				"leakwatch/v1": locationStableFingerprint(fd),
			},
		}

		// Only expose the unredacted secret when explicitly opted in.
		if f.ShowRaw && fd.Raw != "" {
			result.Properties = map[string]string{rawPropertyKey: fd.Raw}
		}

		// Every result gets a location. Sources with a natural file path use
		// it directly; sources without one (e.g. Slack) get a stable
		// synthetic artifactLocation.uri instead of being left location-less,
		// since GitHub Code Scanning does not render location-less results as
		// inline annotations and would otherwise silently drop them from the
		// Security view.
		uri := fd.SourceMetadata.FilePath
		if uri == "" {
			uri = syntheticArtifactURI(fd.SourceMetadata)
		}
		if uri != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}
			if fd.SourceMetadata.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: fd.SourceMetadata.Line}
			}
			result.Locations = []sarifLocation{loc}
		}

		results = append(results, result)
	}

	// Ensure rules is never nil so JSON output is "rules": [] not "rules": null.
	if rules == nil {
		rules = []sarifRule{}
	}

	doc := sarifDocument{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           toolName,
						Version:        f.driverVersion(),
						InformationURI: toolInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("failed to write SARIF output: %w", err)
	}
	return nil
}

// FileExtension returns the SARIF file extension.
func (f *Formatter) FileExtension() string {
	return ".sarif"
}

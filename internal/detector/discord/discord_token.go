// Package discord provides a Discord Bot Token secret detector.
package discord

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var discordTokenPattern = regexp.MustCompile(`[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}`)

// Detector detects Discord Bot Tokens.
type Detector struct{}

// ID returns the unique identifier of the Discord Bot Token detector.
func (d *Detector) ID() string { return "discord-bot-token" }

// Description returns a human-readable description of the Discord Bot Token detector.
func (d *Detector) Description() string { return "Discord Bot Token" }

// Keywords returns the Aho-Corasick pre-filter keywords.
// Discord tokens have no fixed keyword prefix, so an empty slice is returned
// to ensure the regex is applied to every chunk.
func (d *Detector) Keywords() []string { return []string{} }

// Severity returns the default severity level for Discord Bot Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Discord Bot Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := discordTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

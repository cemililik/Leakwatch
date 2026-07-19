// Package ftp provides an FTP/SFTP Credentials secret detector.
package ftp

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Each credential/host segment is bounded to a generous but finite length so
// a single match cannot run away across an entire line of unrelated
// whitespace-free text (e.g. a long minified/concatenated string).
var ftpCredPattern = regexp.MustCompile(`(?:s?ftps?)://[^\s'"]{1,256}:[^\s'"]{1,256}@[^\s'"]{1,256}`)

// Detector detects FTP/SFTP Credentials in connection URLs.
type Detector struct{}

// ID returns the unique identifier of the FTP Credentials detector.
func (d *Detector) ID() string { return "ftp-credentials" }

// Description returns a human-readable description of the FTP Credentials detector.
func (d *Detector) Description() string { return "FTP/SFTP Credentials" }

// Keywords returns the Aho-Corasick pre-filter keywords for FTP Credentials detection.
func (d *Detector) Keywords() []string {
	return []string{"ftp://", "sftp://", "ftps://"}
}

// Severity returns the default severity level for FTP Credentials findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for FTP/SFTP credential patterns.
// The password portion of the URL is redacted in the finding output.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := ftpCredPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   detector.RedactURLPassword(string(match)),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

// Package azure provides Azure secret detectors.
package azure

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// azureStoragePattern captures AccountName and AccountKey directly, so the
// value extraction can never diverge from what the overall pattern matched
// (no separate re-scan, no "not found" fallback to reason about).
var azureStoragePattern = regexp.MustCompile(
	`DefaultEndpointsProtocol=https?;AccountName=([^;]+);AccountKey=([A-Za-z0-9+/=]{86,88});`,
)

// StorageDetector detects Azure Storage Connection Strings.
type StorageDetector struct{}

// ID returns the unique identifier of the Azure Storage detector.
func (d *StorageDetector) ID() string { return "azure-storage-key" }

// Description returns a human-readable description of the Azure Storage detector.
func (d *StorageDetector) Description() string { return "Azure Storage Connection String" }

// Keywords returns the Aho-Corasick pre-filter keywords for Azure Storage detection.
func (d *StorageDetector) Keywords() []string {
	return []string{"DefaultEndpointsProtocol", "AccountKey"}
}

// Severity returns the default severity level for Azure Storage findings.
func (d *StorageDetector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Azure Storage Connection String patterns.
func (d *StorageDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := azureStoragePattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		accountName := string(groups[1])
		accountKey := groups[2]

		// Route AccountKey redaction through the shared Redact helper (same
		// convention as every other detector) instead of hand-rolling a
		// zero-reveal scheme.
		redacted := "AccountName=" + accountName + ";AccountKey=" + detector.Redact(string(accountKey))

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(fullMatch),
			Redacted:   redacted,
			ExtraData: map[string]string{
				"account_name": accountName,
			},
		})
	}
	return findings
}

func init() {
	detector.Register(&StorageDetector{})
}

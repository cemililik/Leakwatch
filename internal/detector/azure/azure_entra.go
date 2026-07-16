package azure

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var azureEntraPattern = regexp.MustCompile(`(?:AZURE_CLIENT_SECRET|azure_client_secret|client_secret)\s*[=:]\s*['"]?([A-Za-z0-9~._-]{34,40})['"]?`)

// EntraDetector detects Azure Entra ID (AAD) Client Secrets.
type EntraDetector struct{}

// ID returns the unique identifier of the Azure Entra ID detector.
func (d *EntraDetector) ID() string { return "azure-entra-secret" }

// Description returns a human-readable description of the Azure Entra ID detector.
func (d *EntraDetector) Description() string { return "Azure Entra ID Client Secret" }

// Keywords returns the Aho-Corasick pre-filter keywords for Azure Entra ID detection.
func (d *EntraDetector) Keywords() []string {
	return []string{"AZURE_CLIENT_SECRET", "azure_client_secret", "client_secret"}
}

// Severity returns the default severity level for Azure Entra ID findings.
func (d *EntraDetector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Azure Entra ID Client Secret patterns.
// The secret value is extracted from the first submatch group.
func (d *EntraDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := azureEntraPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		secretValue := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(secretValue),
			RawV2:      bytes.Clone(fullMatch),
			Redacted:   detector.RedactBytes(secretValue),
		})
	}
	return findings
}

func init() {
	detector.Register(&EntraDetector{})
}

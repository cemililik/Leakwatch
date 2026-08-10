// Package shopify provides a Shopify Access Token secret detector.
package shopify

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var shopifyTokenPattern = regexp.MustCompile(`\bshpat_[a-f0-9]{32}\b`)

// Detector detects Shopify Access Tokens.
type Detector struct{}

func (d *Detector) ID() string { return "shopify-access-token" }

func (d *Detector) Description() string { return "Shopify Access Token" }

func (d *Detector) Keywords() []string { return []string{"shpat_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// AuthoritativeOnOverlap lets the engine prefer this provider-specific token
// over a broad structured-field finding for the same source bytes.
func (d *Detector) AuthoritativeOnOverlap() bool { return true }

// Scan searches the data for Shopify Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := shopifyTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "shpat_****" + s[len(s)-4:],
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

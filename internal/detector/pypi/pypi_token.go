// Package pypi provides a PyPI API Token secret detector.
package pypi

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// pypiTokenPattern is anchored on "AgEIcHlwaS5vcmc", the base64url encoding of
// the fixed macaroon-version header Warehouse (PyPI) prepends to every issued
// token, and requires a substantially longer body — real PyPI tokens are
// 150-200+ characters. The bare "pypi-" + 16-char floor previously used here
// matched plausible non-secret strings (package-mirror URLs, Docker image
// tags, CI job/step names); anchoring on the macaroon prefix, the same
// approach other scanners (gitleaks/trufflehog) use for this token type,
// sharply cuts false positives while keeping true positives.
var pypiTokenPattern = regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`)

// Detector detects PyPI API Tokens.
type Detector struct{}

func (d *Detector) ID() string          { return "pypi-api-token" }
func (d *Detector) Description() string { return "PyPI API Token" }
func (d *Detector) Keywords() []string  { return []string{"pypi-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for PyPI API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := pypiTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		raw := string(match)
		redacted := "pypi-****" + raw[len(raw)-4:]
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

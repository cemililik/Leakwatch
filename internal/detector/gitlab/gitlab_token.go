// Package gitlab provides a GitLab Personal Access Token secret detector.
package gitlab

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	// gitlabTokenPattern matches the classic personal access token (glpat-) as
	// well as the newer routable prefixed token families: deploy (gldt-), runner
	// (glrt-), CI/CD build & trigger (glcbt-/glptt-), OAuth application secret
	// (gloas-), and feed (glft-) tokens. The body quantifier is open-ended
	// ({20,}) so token-length changes under an existing prefix do not silently
	// drop the match.
	gitlabTokenPattern = regexp.MustCompile(`(?:glpat|gldt|glrt|glcbt|glptt|gloas|glft)-[A-Za-z0-9_\-]{20,}`)
	// gitlabHostPattern captures a co-located self-hosted GitLab instance host
	// (any URL whose host contains "gitlab") so the verifier can target the
	// token's true issuer instead of defaulting to gitlab.com. Capture group 1
	// is the bare host (with optional port).
	gitlabHostPattern = regexp.MustCompile(`https?://([a-zA-Z0-9.-]*gitlab[a-zA-Z0-9.-]*(?::\d+)?)`)
)

// Detector detects GitLab Personal Access Tokens.
type Detector struct{}

func (d *Detector) ID() string { return "gitlab-pat" }

func (d *Detector) Description() string { return "GitLab Personal Access Token" }

func (d *Detector) Keywords() []string {
	return []string{"glpat-", "gldt-", "glrt-", "glcbt-", "glptt-", "gloas-", "glft-"}
}

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for GitLab token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := gitlabTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	// Capture a co-located self-hosted GitLab host so the verifier does not
	// misreport a live self-hosted token against gitlab.com. Non-secret context.
	var host string
	if m := gitlabHostPattern.FindSubmatch(data); m != nil {
		host = string(m[1])
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		// Preserve the actual prefix (up to and including the "-") in the
		// redacted form; every match contains a "-" by construction.
		prefixEnd := bytes.IndexByte(match, '-') + 1
		f := detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   string(match[:prefixEnd]) + "****" + string(match[len(match)-4:]),
		}
		if host != "" {
			f.ExtraData = map[string]string{"host": host}
		}
		findings = append(findings, f)
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

// Package twilio provides a Twilio API Key secret detector.
package twilio

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	twilioKeyPattern = regexp.MustCompile(`SK[a-f0-9]{32}`)
	twilioSIDPattern = regexp.MustCompile(`AC[a-f0-9]{32}`)
)

// sidProximityWindow bounds how far (in bytes) from a key match an Account SID
// may sit to be considered part of the same credential. It keeps the SID
// correlation local so that unrelated key/SID pairs in the same chunk are not
// cross-attributed.
const sidProximityWindow = 512

// Detector detects Twilio API Keys.
type Detector struct{}

// ID returns the unique identifier of the Twilio API Key detector.
func (d *Detector) ID() string { return "twilio-api-key" }

// Description returns a human-readable description of the Twilio API Key detector.
func (d *Detector) Description() string { return "Twilio API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Twilio API Key
// detection. The SK API-Key SID pattern is self-contained (a fixed "SK" prefix
// plus 32 hex chars) and carries no guaranteed nearby literal, so returning no
// keywords forces the regex to run on every chunk. Requiring a "twilio" keyword
// would silently gate out standalone keys (e.g. in a secrets-manager dump or
// under a differently named variable).
func (d *Detector) Keywords() []string { return []string{} }

// Severity returns the default severity level for Twilio API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Twilio API Key patterns.
// Account SID (AC prefix) is captured as ExtraData rather than a separate
// finding. The SID is correlated per key match by proximity, so unrelated
// key/SID pairs in the same chunk are not cross-attributed.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	keyLocs := twilioKeyPattern.FindAllIndex(data, -1)
	if len(keyLocs) == 0 {
		return nil
	}

	// Locate every Account SID once, then attach the nearest one to each key.
	sidLocs := twilioSIDPattern.FindAllIndex(data, -1)

	findings := make([]detector.RawFinding, 0, len(keyLocs))
	for _, loc := range keyLocs {
		match := data[loc[0]:loc[1]]
		redacted := "SK****" + string(match[len(match)-4:])
		f := detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redacted,
		}
		if sid := nearestSID(data, loc, sidLocs); sid != "" {
			f.ExtraData = map[string]string{
				"account_sid": sid,
			}
		}
		findings = append(findings, f)
	}
	return findings
}

// nearestSID returns the Account SID closest to the key match at keyLoc, but
// only when it lies within sidProximityWindow bytes. It returns an empty string
// when no SID is close enough, so a key with no nearby SID carries no
// (potentially wrong) account context.
func nearestSID(data []byte, keyLoc []int, sidLocs [][]int) string {
	best := -1
	bestDist := -1
	for i, sid := range sidLocs {
		dist := rangeGap(keyLoc, sid)
		if dist > sidProximityWindow {
			continue
		}
		if bestDist == -1 || dist < bestDist {
			bestDist = dist
			best = i
		}
	}
	if best == -1 {
		return ""
	}
	return string(data[sidLocs[best][0]:sidLocs[best][1]])
}

// rangeGap returns the number of bytes between two non-overlapping [start,end)
// ranges, or 0 when they touch or overlap.
func rangeGap(a, b []int) int {
	switch {
	case a[1] <= b[0]:
		return b[0] - a[1]
	case b[1] <= a[0]:
		return a[0] - b[1]
	default:
		return 0
	}
}

func init() {
	detector.Register(&Detector{})
}

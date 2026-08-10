// Package twilio provides a detector for paired Twilio API Key credentials.
package twilio

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	// An SK value is an API Key SID: a public identifier, not a secret. It is
	// used only as companion context for an explicitly labelled API Key Secret.
	twilioKeySIDPattern     = regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)
	twilioAccountSIDPattern = regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)
	// Twilio API Key Secrets are 32-character alphanumeric values. Requiring an
	// explicit API secret role and a nearby Twilio SK SID avoids reporting an
	// arbitrary identifier or generic 32-character value as a credential.
	twilioAPISecretAssignmentPattern = regexp.MustCompile(`(?i)\b(?:twilio[._-]*)?api[._-]*(?:key[._-]*)?secret["']?\s*[:=]\s*["']?([a-z0-9]{32})(?:["']|[\s,;}#]|$)`)
)

// companionProximityWindow bounds how far a non-secret SID may sit from the
// secret assignment to be treated as the same credential pair.
const companionProximityWindow = 512

// Detector detects Twilio API Key Secrets only when paired with a nearby API
// Key SID. A bare SK SID is intentionally not a finding because it is not
// confidential and cannot authenticate to Twilio.
type Detector struct{}

// ID returns the stable detector identifier.
func (d *Detector) ID() string { return "twilio-api-key" }

// Description returns a human-readable description.
func (d *Detector) Description() string { return "Twilio API Key Secret" }

// Keywords is empty because supported assignment roles include common
// separator and casing variants. Running Scan for every chunk avoids a matcher
// prefilter silently dropping a valid paired credential.
func (d *Detector) Keywords() []string { return []string{} }

// Severity returns the default severity level for a leaked API Key Secret.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// AuthoritativeOnOverlap lets the engine prefer this provider-specific paired
// finding over a structured-config fallback for the same secret bytes.
func (d *Detector) AuthoritativeOnOverlap() bool { return true }

// Scan reports the secret value as Raw and carries only non-secret SIDs in
// ExtraData. It never stores the API Key Secret in ExtraData.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	secretMatches := twilioAPISecretAssignmentPattern.FindAllSubmatchIndex(data, -1)
	if len(secretMatches) == 0 {
		return nil
	}

	keySIDLocs := twilioKeySIDPattern.FindAllIndex(data, -1)
	if len(keySIDLocs) == 0 {
		return nil
	}
	accountSIDLocs := twilioAccountSIDPattern.FindAllIndex(data, -1)

	findings := make([]detector.RawFinding, 0, len(secretMatches))
	for _, match := range secretMatches {
		if len(match) < 4 || match[2] < 0 || match[3] < 0 {
			continue
		}
		secretLoc := []int{match[2], match[3]}
		keySID, keyLoc := nearestValue(data, secretLoc, keySIDLocs)
		if keySID == "" {
			continue
		}

		secret := data[secretLoc[0]:secretLoc[1]]
		extra := map[string]string{"api_key_sid": keySID}
		if accountSID, _ := nearestValue(data, keyLoc, accountSIDLocs); accountSID != "" {
			extra["account_sid"] = accountSID
		}
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(secret),
			Redacted:   "****" + string(secret[len(secret)-4:]),
			ExtraData:  extra,
		})
	}
	return findings
}

// nearestValue returns the value and range closest to target within the local
// companion window.
func nearestValue(data []byte, target []int, candidates [][]int) (string, []int) {
	best := -1
	bestDist := -1
	for i, candidate := range candidates {
		dist := rangeGap(target, candidate)
		if dist > companionProximityWindow {
			continue
		}
		if bestDist == -1 || dist < bestDist {
			bestDist = dist
			best = i
		}
	}
	if best == -1 {
		return "", nil
	}
	loc := candidates[best]
	return string(data[loc[0]:loc[1]]), loc
}

// rangeGap returns the byte distance between two non-overlapping ranges.
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

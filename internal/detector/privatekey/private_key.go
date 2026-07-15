// Package privatekey provides private key detectors.
package privatekey

import (
	"bytes"
	"context"
	"regexp"
	"strconv"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	// privateKeyPattern matches the BEGIN armor for every PEM private-key
	// label this detector covers: the classic RSA/OPENSSH/DSA/EC/PGP labels,
	// the bare PKCS8 "PRIVATE KEY" label, and PKCS8's password-protected
	// "ENCRYPTED PRIVATE KEY" label. The optional prefix group accepts any
	// run of uppercase-word tokens before the literal "PRIVATE KEY" so new
	// all-caps labels (e.g. a future PKCS8 variant) are covered without
	// another edit here. See review section 04-detectors-d3.md HIGH finding
	// "private_key.go:14" (ENCRYPTED PRIVATE KEY armor was previously
	// unmatched).
	privateKeyPattern = regexp.MustCompile(`-----BEGIN\s+(?:[A-Z0-9]+\s+)*PRIVATE KEY( BLOCK)?-----`)
	// privateKeyEndPattern locates the closing armor so the full PEM block
	// region can be measured without retaining the key body between them.
	privateKeyEndPattern = regexp.MustCompile(`-----END\s+(?:[A-Z0-9]+\s+)*PRIVATE KEY(?: BLOCK)?-----`)
)

// Detector detects PEM-encoded private keys.
type Detector struct{}

func (d *Detector) ID() string { return "private-key" }

func (d *Detector) Description() string { return "Private Key (RSA, SSH, DSA, EC, PGP)" }
func (d *Detector) Keywords() []string {
	return []string{
		"-----BEGIN RSA PRIVATE",
		"-----BEGIN OPENSSH PRIVATE",
		"-----BEGIN DSA PRIVATE",
		"-----BEGIN EC PRIVATE",
		"-----BEGIN PGP PRIVATE",
		"-----BEGIN PRIVATE KEY",
		"-----BEGIN ENCRYPTED PRIVATE",
	}
}
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for PEM private key blocks. It locates the BEGIN/END
// armor pair so the full block REGION is captured for span/dedup purposes, but
// it never stores the key body: Raw holds only the BEGIN header and the byte
// span of the block is reported via ExtraData. The PEM body between the armor
// lines is deliberately discarded.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	locs := privateKeyPattern.FindAllIndex(data, -1)
	if len(locs) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(locs))
	for i, loc := range locs {
		header := data[loc[0]:loc[1]]

		// Determine the block region by finding the next END armor after the
		// header. We only record its length, never the bytes in between.
		//
		// The search for that END armor is bounded to end at the next BEGIN
		// armor (if any): without this bound, a BEGIN with no END of its own
		// (e.g. a truncated/malformed block, or simply two BEGIN headers back
		// to back) would let the search run past an unrelated adjacent key
		// block and report a block_bytes span that incorrectly includes that
		// second key's header and body. See review section 04-detectors-d3.md
		// LOW finding "private_key.go:56".
		blockLen := loc[1] - loc[0]
		searchEnd := len(data)
		if i+1 < len(locs) {
			searchEnd = locs[i+1][0]
		}
		if end := privateKeyEndPattern.FindIndex(data[loc[1]:searchEnd]); end != nil {
			blockLen = (loc[1] + end[1]) - loc[0]
		} else if i+1 < len(locs) {
			// No END armor before the next BEGIN: cap the block region at the
			// next BEGIN so it never spans into the unrelated adjacent block.
			blockLen = locs[i+1][0] - loc[0]
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			// Raw is the header only, cloned so it does not keep the whole
			// scanned chunk buffer alive for the rest of the scan (see
			// review section 04-detectors-d3.md MED finding on Raw aliasing).
			// The key body is never retained.
			Raw:      bytes.Clone(header),
			Redacted: "-----BEGIN [REDACTED] PRIVATE KEY-----",
			ExtraData: map[string]string{
				"block_bytes": strconv.Itoa(blockLen),
			},
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}

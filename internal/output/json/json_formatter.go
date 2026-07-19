// Package json provides a JSON output formatter.
package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Formatter outputs findings in JSON format.
type Formatter struct {
	// ShowRaw controls whether the raw secret value is included in output.
	// finding.Finding.Raw carries a json:"-" tag, so it is never serialized by
	// default. When ShowRaw is true, each finding is marshaled through the
	// findingJSON wire type below to explicitly opt the value back in.
	ShowRaw bool
}

// findingJSON is the wire type used to opt the raw secret value and non-secret
// extra metadata back into JSON output when ShowRaw is enabled. It embeds
// finding.Finding (whose Raw and ExtraData fields are both json:"-") and
// re-adds a "raw" field mirroring finding.Finding.Raw plus an "extra_data"
// field mirroring finding.Finding.ExtraData. ExtraData is defense-in-depth
// gated the same way Raw is: it must never carry secret material (see
// finding.Finding's doc comment), but it is still opt-in behind --show-raw
// alongside Raw so it does not appear in default output either.
type findingJSON struct {
	finding.Finding
	Raw       string            `json:"raw,omitempty"`
	ExtraData map[string]string `json:"extra_data,omitempty"`
}

// Format writes findings as JSON to the given writer.
// When ShowRaw is false, finding.Finding is marshaled directly and both the
// raw secret and ExtraData are omitted by their json:"-" tags. When ShowRaw is
// true, each finding is marshaled via findingJSON so the raw value and any
// non-secret ExtraData are explicitly included.
func (f *Formatter) Format(w io.Writer, findings []finding.Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if !f.ShowRaw {
		if err := encoder.Encode(findings); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}
		return nil
	}

	output := make([]findingJSON, len(findings))
	for i, fd := range findings {
		output[i] = findingJSON{Finding: fd, Raw: fd.Raw, ExtraData: fd.ExtraData}
	}
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}
	return nil
}

// FileExtension returns the JSON file extension.
func (f *Formatter) FileExtension() string {
	return ".json"
}

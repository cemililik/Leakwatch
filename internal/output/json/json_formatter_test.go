package json

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatter_Format_EmptyFindings_WritesEmptyArray(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)

	var result []finding.Finding
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestFormatter_Format_SingleFinding_WritesValidJSON(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "abc123",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				SourceType: "filesystem",
				FilePath:   "config.yaml",
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var result []finding.Finding
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "aws-access-key-id", result[0].DetectorID)
	assert.Equal(t, "AKIA****MPLE", result[0].Redacted)
}

func TestFormatter_Format_OmitsRawWhenEmpty(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{ID: "test", Redacted: "****"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	_, hasRaw := rawJSON[0]["raw"]
	assert.False(t, hasRaw, "raw field should not appear in JSON when empty")
}

func TestFormatter_Format_ShowRawFalse_StripsRawFromOutput(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:       "test-1",
			Redacted: "AKIA****MPLE",
			Raw:      "AKIAIOSFODNN7EXAMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	_, hasRaw := rawJSON[0]["raw"]
	assert.False(t, hasRaw, "Raw field should not appear when ShowRaw=false")
}

func TestFormatter_Format_ShowRawTrue_IncludesRawInOutput(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:       "test-1",
			Redacted: "AKIA****MPLE",
			Raw:      "AKIAIOSFODNN7EXAMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	rawVal, hasRaw := rawJSON[0]["raw"]
	assert.True(t, hasRaw, "Raw field should appear when ShowRaw=true")
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", rawVal)
}

// TestFormatter_Format_DefaultShape_MatchesStandardFindingMarshal verifies the
// default (ShowRaw=false) output is byte-identical to standard json.Marshal of
// the findings slice, i.e. the wire type does not change the no-raw shape.
func TestFormatter_Format_DefaultShape_MatchesStandardFindingMarshal(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "abc123",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			Raw:        "AKIAIOSFODNN7EXAMPLE",
			SourceMetadata: finding.SourceMetadata{
				SourceType: "filesystem",
				FilePath:   "config.yaml",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	expected, err := json.MarshalIndent(findings, "", "  ")
	require.NoError(t, err)

	// json.Encoder appends a trailing newline; MarshalIndent does not.
	assert.Equal(t, string(expected)+"\n", buf.String(),
		"default JSON output shape must match standard json.Marshal of []finding.Finding")
	assert.NotContains(t, buf.String(), "AKIAIOSFODNN7EXAMPLE",
		"raw secret must never appear in default output")
}

func TestFormatter_Format_ShowRawFalse_ExtraDataNotInOutput(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:        "test-1",
			Redacted:  "****",
			ExtraData: map[string]string{"host": "api.example.com"},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	_, hasExtraData := rawJSON[0]["extra_data"]
	assert.False(t, hasExtraData, "extra_data must not appear when ShowRaw=false")
}

func TestFormatter_Format_ShowRawTrue_IncludesExtraDataInOutput(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:        "test-1",
			Redacted:  "****",
			ExtraData: map[string]string{"host": "api.example.com", "username": "alice"},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	extraData, hasExtraData := rawJSON[0]["extra_data"]
	require.True(t, hasExtraData, "extra_data should appear when ShowRaw=true and populated")
	extraDataMap, ok := extraData.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "api.example.com", extraDataMap["host"])
	assert.Equal(t, "alice", extraDataMap["username"])
}

func TestFormatter_Format_ShowRawTrue_OmitsExtraDataWhenNil(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{ID: "test-1", Redacted: "****"},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	_, hasExtraData := rawJSON[0]["extra_data"]
	assert.False(t, hasExtraData, "extra_data should be omitted when nil, even with ShowRaw=true")
}

func TestFormatter_Format_ShowRaw_PreservesNullableFindingFields(t *testing.T) {
	formatted := finding.Finding{ID: "computed-zero", Raw: "synthetic-secret"}
	formatted.SetEntropy(0)

	var buf bytes.Buffer
	require.NoError(t, (&Formatter{ShowRaw: true}).Format(&buf, []finding.Finding{formatted}))

	var output []map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &output))
	require.Len(t, output, 1)
	assert.NotContains(t, output[0], "detected_at")
	assert.Equal(t, float64(0), output[0]["entropy"])
	assert.Equal(t, "synthetic-secret", output[0]["raw"])
}

func TestFormatter_Format_ShowRawFalse_DoesNotMutateOriginal(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:  "test-1",
			Raw: "AKIAIOSFODNN7EXAMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", findings[0].Raw, "Format should not mutate the original slice")
}

func TestFormatter_FileExtension_ReturnsJSON(t *testing.T) {
	f := &Formatter{}
	assert.Equal(t, ".json", f.FileExtension())
}

// errWriter simulates a write error.
type errWriter struct{}

func (w *errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestFormatter_Format_WriterError_ReturnsError(t *testing.T) {
	f := &Formatter{}
	findings := []finding.Finding{{ID: "test"}}

	err := f.Format(&errWriter{}, findings)
	assert.Error(t, err)
}

func TestFormatter_Format_WithRemediation_IncludesRemediationInOutput(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "rem-1",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			Remediation: &finding.Remediation{
				Title:   "Rotate AWS Access Key",
				Steps:   []string{"Deactivate the key in IAM", "Create a new key", "Update all consumers"},
				DocURL:  "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
				Urgency: "immediate",
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	rem, hasRemediation := rawJSON[0]["remediation"]
	assert.True(t, hasRemediation, "remediation field should appear in JSON when populated")

	remMap, ok := rem.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Rotate AWS Access Key", remMap["title"])
	assert.Equal(t, "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", remMap["doc_url"])
	assert.Equal(t, "immediate", remMap["urgency"])

	steps, ok := remMap["steps"].([]interface{})
	require.True(t, ok)
	assert.Len(t, steps, 3)
}

func TestFormatter_Format_WithoutRemediation_OmitsRemediationFromOutput(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:       "no-rem-1",
			Redacted: "****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var rawJSON []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &rawJSON)
	require.NoError(t, err)

	_, hasRemediation := rawJSON[0]["remediation"]
	assert.False(t, hasRemediation, "remediation field should not appear in JSON when nil")
}

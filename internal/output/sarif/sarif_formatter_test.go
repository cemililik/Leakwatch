package sarif

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatter_Format_EmptyFindings_WritesValidSARIFWithEmptyResults(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	assert.Equal(t, sarifSchema, doc.Schema)
	assert.Equal(t, sarifVersion, doc.Version)
	require.Len(t, doc.Runs, 1)
	assert.Equal(t, toolName, doc.Runs[0].Tool.Driver.Name)
	assert.Empty(t, doc.Runs[0].Tool.Driver.Rules)
	assert.Empty(t, doc.Runs[0].Results)
}

func TestFormatter_Format_SingleFinding_WritesCorrectRuleAndResult(t *testing.T) {
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
				Line:       42,
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	// Verify rule.
	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	assert.Equal(t, "aws-access-key-id", rule.ID)
	assert.Equal(t, "error", rule.DefaultConfig.Level)

	// Verify result.
	require.Len(t, doc.Runs[0].Results, 1)
	result := doc.Runs[0].Results[0]
	assert.Equal(t, "aws-access-key-id", result.RuleID)
	assert.Equal(t, 0, result.RuleIndex)
	assert.Equal(t, "error", result.Level)
	assert.Contains(t, result.Message.Text, "AKIA****MPLE")

	// Verify location.
	require.Len(t, result.Locations, 1)
	loc := result.Locations[0].PhysicalLocation
	assert.Equal(t, "config.yaml", loc.ArtifactLocation.URI)
	require.NotNil(t, loc.Region)
	assert.Equal(t, 42, loc.Region.StartLine)
}

func TestFormatter_Format_ShowRawFalse_RawNotInOutput(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityHigh,
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "app.go",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "sk_live_supersecretvalue",
		"ShowRaw=false must strip raw secret from SARIF output")
}

func TestFormatter_Format_ShowRawTrue_RawInResultProperties(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityHigh,
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "app.go",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	require.Len(t, doc.Runs[0].Results, 1)
	props := doc.Runs[0].Results[0].Properties
	require.NotNil(t, props, "ShowRaw=true must populate result properties")
	assert.Equal(t, "sk_live_supersecretvalue", props["raw"],
		"ShowRaw=true must expose the raw value under properties.raw")
}

func TestFormatter_Format_ShowRawFalse_NoRawProperty(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityHigh,
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	require.Len(t, doc.Runs[0].Results, 1)
	assert.Nil(t, doc.Runs[0].Results[0].Properties,
		"ShowRaw=false must not emit any result properties carrying raw")
	assert.NotContains(t, buf.String(), "sk_live_supersecretvalue")
}

func TestFormatter_Format_Driver_HasVersionAndInformationURI(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	driver := doc.Runs[0].Tool.Driver
	assert.Equal(t, toolName, driver.Name)
	assert.Equal(t, defaultToolVersion, driver.Version,
		"a zero-value Formatter (no Version set) must fall back to defaultToolVersion")
	assert.Equal(t, toolInfoURI, driver.InformationURI, "driver must report an informationUri")
}

// TestFormatter_Format_Driver_UsesInjectedVersion asserts against a real,
// non-default version string so this test would actually fail if
// Formatter.Version stopped being threaded into tool.driver.version (unlike
// the old test, which compared the constant against itself).
func TestFormatter_Format_Driver_UsesInjectedVersion(t *testing.T) {
	f := &Formatter{Version: "v1.6.0"}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	driver := doc.Runs[0].Tool.Driver
	assert.Equal(t, "v1.6.0", driver.Version)
	assert.NotEqual(t, defaultToolVersion, driver.Version)
}

func TestFormatter_Format_SeverityMapping_MapsCorrectly(t *testing.T) {
	tests := []struct {
		name     string
		severity finding.Severity
		expected string
	}{
		{"Critical maps to error", finding.SeverityCritical, "error"},
		{"High maps to warning", finding.SeverityHigh, "warning"},
		{"Medium maps to note", finding.SeverityMedium, "note"},
		{"Low maps to note", finding.SeverityLow, "note"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Formatter{}
			var buf bytes.Buffer

			findings := []finding.Finding{
				{
					ID:         "sev-test",
					DetectorID: "test-detector",
					Severity:   tt.severity,
					Redacted:   "****",
				},
			}

			err := f.Format(&buf, findings)
			require.NoError(t, err)

			var doc sarifDocument
			err = json.Unmarshal(buf.Bytes(), &doc)
			require.NoError(t, err)

			require.Len(t, doc.Runs[0].Results, 1)
			assert.Equal(t, tt.expected, doc.Runs[0].Results[0].Level)
		})
	}
}

func TestFormatter_Format_ShowRawFalse_DoesNotMutateOriginal(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic",
			Raw:        "AKIAIOSFODNN7EXAMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", findings[0].Raw,
		"Format must not mutate the original slice")
}

func TestFormatter_Format_WithRemediation_RuleHasHelpAndHelpURI(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "rem-1",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.yaml",
			},
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

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
	rule := doc.Runs[0].Tool.Driver.Rules[0]

	require.NotNil(t, rule.Help, "rule should have help when remediation is present")
	assert.Contains(t, rule.Help.Text, "Deactivate the key in IAM")
	assert.Contains(t, rule.Help.Text, "Create a new key")
	assert.Contains(t, rule.Help.Text, "Update all consumers")
	assert.Equal(t, "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", rule.HelpURI)
}

func TestFormatter_Format_WithoutRemediation_RuleHasNoHelp(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "no-rem-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityMedium,
			Redacted:   "****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	err = json.Unmarshal(buf.Bytes(), &doc)
	require.NoError(t, err)

	require.Len(t, doc.Runs[0].Tool.Driver.Rules, 1)
	rule := doc.Runs[0].Tool.Driver.Rules[0]
	assert.Nil(t, rule.Help, "rule should not have help when remediation is absent")
	assert.Empty(t, rule.HelpURI, "rule should not have helpUri when remediation is absent")
}

func TestFormatter_Format_SlackSource_GetsSyntheticLocation(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "slack-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityHigh,
			Redacted:   "sk_****abcd",
			SourceMetadata: finding.SourceMetadata{
				SourceType:  "slack",
				Channel:     "C0123456",
				ChannelName: "secrets-oops",
				MessageTS:   "1699999999.000100",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.Len(t, doc.Runs[0].Results, 1)
	result := doc.Runs[0].Results[0]
	require.Len(t, result.Locations, 1,
		"a Slack-sourced finding must not be emitted without a locations entry")
	assert.Equal(t, "slack://secrets-oops/1699999999.000100", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Nil(t, result.Locations[0].PhysicalLocation.Region, "Slack findings have no line region")
}

func TestFormatter_Format_SlackSource_FallsBackToChannelIDWhenNameMissing(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "slack-2",
			DetectorID: "generic-secret",
			SourceMetadata: finding.SourceMetadata{
				SourceType: "slack",
				Channel:    "C0123456",
				MessageTS:  "1700000000.000200",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.Len(t, doc.Runs[0].Results, 1)
	require.Len(t, doc.Runs[0].Results[0].Locations, 1)
	assert.Equal(t, "slack://C0123456/1700000000.000200",
		doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestFormatter_Format_UnknownNonFileSource_StaysLocationLess(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "no-loc-1",
			DetectorID: "generic-secret",
			SourceMetadata: finding.SourceMetadata{
				SourceType: "some-future-source",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	var doc sarifDocument
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	require.Len(t, doc.Runs[0].Results, 1)
	assert.Empty(t, doc.Runs[0].Results[0].Locations,
		"a source type with neither a file path nor synthetic-URI support stays location-less")
}

func TestFormatter_FileExtension_ReturnsSARIF(t *testing.T) {
	f := &Formatter{}
	assert.Equal(t, ".sarif", f.FileExtension())
}

func TestFormatter_Format_PartialFingerprints_LocationIndependent(t *testing.T) {
	// The same secret in the same file on two different lines must produce the
	// SAME partial fingerprint, so GitHub Code Scanning tracks one alert across
	// line moves rather than churning it.
	findings := []finding.Finding{
		{
			ID: "id-line-2", DetectorID: "aws-access-key-id", Severity: finding.SeverityCritical, Redacted: "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{FilePath: "a.txt", Line: 2},
		},
		{
			ID: "id-line-9", DetectorID: "aws-access-key-id", Severity: finding.SeverityCritical, Redacted: "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{FilePath: "a.txt", Line: 9},
		},
		{
			ID: "id-other", DetectorID: "aws-access-key-id", Severity: finding.SeverityCritical, Redacted: "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{FilePath: "b.txt", Line: 2},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, (&Formatter{}).Format(&buf, findings))

	var doc map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)

	fp := func(i int) string {
		return results[i].(map[string]any)["partialFingerprints"].(map[string]any)["leakwatch/v1"].(string)
	}
	assert.NotEmpty(t, fp(0))
	assert.Equal(t, fp(0), fp(1), "same secret + same file, different line → same fingerprint")
	assert.NotEqual(t, fp(0), fp(2), "different file → different fingerprint")
}

// TestSyntheticArtifactURI_StripsChannelHash pins that a Slack channel name is
// not emitted with its leading '#': in a URI '#' starts the fragment, so
// "slack://#general/..." would parse as an empty authority plus a fragment.
func TestSyntheticArtifactURI_StripsChannelHash(t *testing.T) {
	tests := []struct {
		name string
		meta finding.SourceMetadata
		want string
	}{
		{
			name: "channel name with leading hash",
			meta: finding.SourceMetadata{SourceType: "slack", ChannelName: "#general", MessageTS: "1700000000.1"},
			want: "slack://general/1700000000.1",
		},
		{
			name: "falls back to channel id, also stripped",
			meta: finding.SourceMetadata{SourceType: "slack", Channel: "#C123", MessageTS: "1700000000.2"},
			want: "slack://C123/1700000000.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syntheticArtifactURI(tt.meta)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, "#", "a '#' would be parsed as a URI fragment")
		})
	}
}

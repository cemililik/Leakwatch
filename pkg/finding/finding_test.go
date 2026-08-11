package finding

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
		ok       bool
	}{
		{"low", SeverityLow, true},
		{"medium", SeverityMedium, true},
		{"high", SeverityHigh, true},
		{"critical", SeverityCritical, true},
		{"HIGH", SeverityLow, false},   // case-sensitive: not recognized
		{"crital", SeverityLow, false}, // typo: not recognized
		{"", SeverityLow, false},       // empty: not recognized
		{"unknown", SeverityLow, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			sev, ok := ParseSeverity(tt.input)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.expected, sev)
			}
		})
	}
}

func TestVerificationStatus_String(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected string
	}{
		{StatusUnverified, "unverified"},
		{StatusVerifiedActive, "verified_active"},
		{StatusVerifiedInactive, "verified_inactive"},
		{StatusVerifyError, "verify_error"},
		{VerificationStatus(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestSeverity_MarshalJSON_StringRepresentation(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		expected string
	}{
		{"low", SeverityLow, `"low"`},
		{"medium", SeverityMedium, `"medium"`},
		{"high", SeverityHigh, `"high"`},
		{"critical", SeverityCritical, `"critical"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.severity)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestSeverity_MarshalJSON_InvalidValue_ReturnsError(t *testing.T) {
	_, err := json.Marshal(Severity(99))
	assert.Error(t, err)
}

func TestSeverity_UnmarshalJSON_RoundTrip_PreservesValue(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
	}{
		{"low", SeverityLow},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"critical", SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.severity)
			require.NoError(t, err)

			var decoded Severity
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.severity, decoded)
		})
	}
}

func TestSeverity_UnmarshalJSON_InvalidString_ReturnsError(t *testing.T) {
	var s Severity
	err := json.Unmarshal([]byte(`"bogus"`), &s)
	assert.Error(t, err)
}

func TestSeverity_UnmarshalJSON_InvalidType_ReturnsError(t *testing.T) {
	var s Severity
	err := json.Unmarshal([]byte(`3`), &s)
	assert.Error(t, err)
}

func TestVerificationStatus_MarshalJSON_StringRepresentation(t *testing.T) {
	tests := []struct {
		name     string
		status   VerificationStatus
		expected string
	}{
		{"unverified", StatusUnverified, `"unverified"`},
		{"verified_active", StatusVerifiedActive, `"verified_active"`},
		{"verified_inactive", StatusVerifiedInactive, `"verified_inactive"`},
		{"verify_error", StatusVerifyError, `"verify_error"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestVerificationStatus_MarshalJSON_InvalidValue_ReturnsError(t *testing.T) {
	_, err := json.Marshal(VerificationStatus(99))
	assert.Error(t, err)
}

func TestVerificationStatus_UnmarshalJSON_RoundTrip_PreservesValue(t *testing.T) {
	tests := []struct {
		name   string
		status VerificationStatus
	}{
		{"unverified", StatusUnverified},
		{"verified_active", StatusVerifiedActive},
		{"verified_inactive", StatusVerifiedInactive},
		{"verify_error", StatusVerifyError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			require.NoError(t, err)

			var decoded VerificationStatus
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.status, decoded)
		})
	}
}

func TestVerificationStatus_UnmarshalJSON_InvalidString_ReturnsError(t *testing.T) {
	var v VerificationStatus
	err := json.Unmarshal([]byte(`"bogus"`), &v)
	assert.Error(t, err)
}

func TestVerificationStatus_UnmarshalJSON_InvalidType_ReturnsError(t *testing.T) {
	var v VerificationStatus
	err := json.Unmarshal([]byte(`0`), &v)
	assert.Error(t, err)
}

func TestFinding_JSONMarshalUnmarshal_SeverityAsString(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	f := Finding{
		ID:         "test-123",
		DetectorID: "aws-access-key-id",
		Severity:   SeverityCritical,
		Redacted:   "AKIA****MPLE",
		SourceMetadata: SourceMetadata{
			SourceType: "filesystem",
			FilePath:   "config.yaml",
			Line:       42,
		},
		Verification: VerificationResult{
			Status: StatusUnverified,
		},
		DetectedAt: now,
	}
	f.SetEntropy(4.5)

	data, err := json.Marshal(f)
	require.NoError(t, err)

	// Severity should serialize as "critical" string, not integer 3
	var rawJSON map[string]interface{}
	err = json.Unmarshal(data, &rawJSON)
	require.NoError(t, err)
	assert.Equal(t, "critical", rawJSON["severity"], "Severity should serialize as string in JSON")

	// Verification status should also appear as string
	verification, ok := rawJSON["verification"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "unverified", verification["status"], "VerificationStatus should serialize as string in JSON")

	var decoded Finding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, f.ID, decoded.ID)
	assert.Equal(t, f.DetectorID, decoded.DetectorID)
	assert.Equal(t, f.Severity, decoded.Severity)
	assert.Equal(t, f.Redacted, decoded.Redacted)
	assert.Equal(t, f.SourceMetadata.FilePath, decoded.SourceMetadata.FilePath)
	assert.Equal(t, f.SourceMetadata.Line, decoded.SourceMetadata.Line)
	assert.Equal(t, f.Verification.Status, decoded.Verification.Status)
	assert.True(t, decoded.EntropyCalculated)
	assert.Equal(t, 4.5, decoded.Entropy)
	assert.Empty(t, decoded.Raw) // Raw is never serialized via json:"-"
}

func TestFinding_JSONNullableEntropyAndDetectedAt(t *testing.T) {
	t.Run("missing values are omitted", func(t *testing.T) {
		data, err := json.Marshal(Finding{ID: "test-1"})
		require.NoError(t, err)

		var object map[string]any
		require.NoError(t, json.Unmarshal(data, &object))
		assert.NotContains(t, object, "detected_at")
		assert.NotContains(t, object, "entropy")
		assert.NotContains(t, string(data), "0001-01-01")
	})

	t.Run("computed zero is present and round trips", func(t *testing.T) {
		original := Finding{ID: "test-2"}
		original.SetEntropy(0)

		data, err := json.Marshal(original)
		require.NoError(t, err)
		var object map[string]any
		require.NoError(t, json.Unmarshal(data, &object))
		value, exists := object["entropy"]
		require.True(t, exists)
		assert.Equal(t, float64(0), value)

		var decoded Finding
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.True(t, decoded.EntropyCalculated)
		assert.Zero(t, decoded.Entropy)
	})

	t.Run("legacy non-zero entropy remains source compatible", func(t *testing.T) {
		data, err := json.Marshal(Finding{ID: "test-3", Entropy: 3.5})
		require.NoError(t, err)
		assert.Contains(t, string(data), `"entropy":3.5`)
	})

	t.Run("missing values clear a reused destination", func(t *testing.T) {
		destination := Finding{DetectedAt: time.Now().UTC()}
		destination.SetEntropy(4.2)
		require.NoError(t, json.Unmarshal([]byte(`{"id":"replacement"}`), &destination))
		assert.Equal(t, "replacement", destination.ID)
		assert.True(t, destination.DetectedAt.IsZero())
		assert.Zero(t, destination.Entropy)
		assert.False(t, destination.EntropyCalculated)
	})
}

func TestFinding_JSONOmitsEmptyRaw(t *testing.T) {
	f := Finding{
		ID:       "test-1",
		Redacted: "AKIA****MPLE",
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	_, hasRaw := m["raw"]
	assert.False(t, hasRaw, "raw field should not appear in JSON when empty")
}

// TestFinding_JSONNeverSerializesRaw verifies the type-level redaction: even
// when Raw holds a (fake) secret, the standard json.Marshal MUST NOT emit it.
// This is the defense that protects external consumers which marshal Findings
// directly without going through Leakwatch's output formatters.
func TestFinding_JSONNeverSerializesRaw(t *testing.T) {
	f := Finding{
		ID:       "test-1",
		Redacted: "AKIA****MPLE",
		Raw:      "AKIAIOSFODNN7EXAMPLE", // fake, well-known AWS docs example value
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "AKIAIOSFODNN7EXAMPLE",
		"Raw must never appear in standard JSON output")

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	_, hasRaw := m["raw"]
	assert.False(t, hasRaw, "raw field must never appear in JSON regardless of value")
}

// TestFinding_JSONNeverSerializesExtraData verifies the defense-in-depth gate:
// even if a detector mistakenly stashes secret material in ExtraData, standard
// json.Marshal of a Finding (the default, non --show-raw output path) MUST NOT
// emit it. This mirrors the Raw protection above.
func TestFinding_JSONNeverSerializesExtraData(t *testing.T) {
	f := Finding{
		ID:       "test-1",
		Redacted: "snowflakecomputing.com?password=****",
		ExtraData: map[string]string{
			"password": "SuperSecretPW1", // fake value; must never reach output
		},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "SuperSecretPW1",
		"ExtraData must never appear in default JSON output")

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	_, hasExtra := m["extra_data"]
	assert.False(t, hasExtra, "extra_data must never appear in default JSON output")
}

// TestSourceMetadata_JSONOmitsZeroDate verifies that a non-git source (which
// never sets Date) does not serialize a bogus zero timestamp. omitempty is a
// no-op on time.Time, so this is enforced by the custom MarshalJSON.
func TestSourceMetadata_JSONOmitsZeroDate(t *testing.T) {
	f := Finding{
		ID:         "test-1",
		DetectedAt: time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC),
		SourceMetadata: SourceMetadata{
			SourceType: "filesystem",
			FilePath:   "config.yaml",
			Line:       42,
		},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "0001-01-01",
		"a zero source Date must never serialize as 0001-01-01T00:00:00Z")

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)
	source, ok := m["source"].(map[string]interface{})
	require.True(t, ok)
	_, hasDate := source["date"]
	assert.False(t, hasDate, "date key must be absent when Date is the zero time")
}

// TestSourceMetadata_JSONIncludesNonZeroDate verifies that a git source's real
// commit date is still serialized under the "date" key.
func TestSourceMetadata_JSONIncludesNonZeroDate(t *testing.T) {
	when := time.Date(2023, 5, 1, 12, 0, 0, 0, time.UTC)
	f := Finding{
		ID: "test-1",
		SourceMetadata: SourceMetadata{
			SourceType: "git",
			Repository: "example/repo",
			Date:       when,
		},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)
	source, ok := m["source"].(map[string]interface{})
	require.True(t, ok)
	date, hasDate := source["date"]
	require.True(t, hasDate, "date key must be present when Date is set")
	assert.Equal(t, "2023-05-01T12:00:00Z", date)
}

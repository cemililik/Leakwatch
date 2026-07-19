package custom

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFromDef_ValidRule_ReturnsDetector(t *testing.T) {
	def := RuleDef{
		ID:          "internal-api-key",
		Description: "Internal API Key",
		Regex:       `INTERNAL_[A-Z0-9]{32}`,
		Keywords:    []string{"INTERNAL_"},
		Severity:    "high",
	}

	det, err := NewFromDef(def)
	require.NoError(t, err)
	assert.Equal(t, "internal-api-key", det.ID())
	assert.Equal(t, "Internal API Key", det.Description())
	assert.Equal(t, finding.SeverityHigh, det.Severity())
	assert.Equal(t, []string{"INTERNAL_"}, det.Keywords())
}

func TestNewFromDef_EmptyID_ReturnsError(t *testing.T) {
	def := RuleDef{Regex: `test`}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID is required")
}

func TestNewFromDef_EmptyRegex_ReturnsError(t *testing.T) {
	def := RuleDef{ID: "test"}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "regex is required")
}

func TestNewFromDef_InvalidRegex_ReturnsError(t *testing.T) {
	def := RuleDef{ID: "test", Regex: `[unclosed`}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex")
}

func TestNewFromDef_RegexTooLong_ReturnsError(t *testing.T) {
	longRegex := strings.Repeat("a", maxRegexLength+1)
	def := RuleDef{ID: "test", Regex: longRegex}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestCustomDetector_Scan_MatchFound_ReturnsFinding(t *testing.T) {
	def := RuleDef{
		ID:    "test-pattern",
		Regex: `TOKEN_[A-Z0-9]{16}`,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	findings := det.Scan(context.Background(), []byte("found TOKEN_ABCDEF1234567890 here"))
	require.Len(t, findings, 1)
	assert.Equal(t, "test-pattern", findings[0].DetectorID)
	assert.Equal(t, "****7890", findings[0].Redacted)
}

// TestCustomDetector_Scan_RawIsClonedNotAliased verifies Raw does not alias
// the scanned chunk buffer (memory/aliasing hardening).
func TestCustomDetector_Scan_RawIsClonedNotAliased(t *testing.T) {
	def := RuleDef{ID: "test-pattern", Regex: `TOKEN_[A-Z0-9]{16}`}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	data := []byte("found TOKEN_ABCDEF1234567890 here")
	findings := det.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	rawBefore := string(findings[0].Raw)
	for i := range data {
		data[i] = 'x'
	}
	assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
}

func TestCustomDetector_Scan_NoMatch_ReturnsNil(t *testing.T) {
	def := RuleDef{
		ID:    "test-pattern",
		Regex: `TOKEN_[A-Z0-9]{16}`,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	findings := det.Scan(context.Background(), []byte("no secrets here"))
	assert.Nil(t, findings)
}

func TestCustomDetector_Scan_LowEntropy_SkipsMatch(t *testing.T) {
	def := RuleDef{
		ID:      "test-entropy",
		Regex:   `KEY_[A-Za-z0-9]{16}`,
		Entropy: 3.5,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	// Low entropy: repeating characters
	findings := det.Scan(context.Background(), []byte("KEY_AAAAAAAAAAAAAAAA"))
	assert.Empty(t, findings, "low entropy match should be skipped")
}

func TestCustomDetector_Scan_HighEntropy_ReturnsFinding(t *testing.T) {
	def := RuleDef{
		ID:      "test-entropy",
		Regex:   `KEY_[A-Za-z0-9]{16}`,
		Entropy: 2.0,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	findings := det.Scan(context.Background(), []byte("KEY_aB3kL9mN2pQ7rT4x"))
	assert.Len(t, findings, 1)
}

func TestCustomDetector_Severity_DefaultsMedium(t *testing.T) {
	def := RuleDef{ID: "test", Regex: `test`}
	det, err := NewFromDef(def)
	require.NoError(t, err)
	assert.Equal(t, finding.SeverityMedium, det.Severity())
}

// TestNewFromDef_Severity_TableDriven exercises every recognized severity
// value plus the empty-default and unrecognized-value (typo/casing mistake)
// cases. A non-empty, unrecognized severity must return an error rather than
// being silently downgraded to medium.
func TestNewFromDef_Severity_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		severity  string
		wantErr   bool
		wantLevel finding.Severity
	}{
		{name: "critical", severity: "critical", wantLevel: finding.SeverityCritical},
		{name: "high", severity: "high", wantLevel: finding.SeverityHigh},
		{name: "medium explicit", severity: "medium", wantLevel: finding.SeverityMedium},
		{name: "low", severity: "low", wantLevel: finding.SeverityLow},
		{name: "empty defaults to medium", severity: "", wantLevel: finding.SeverityMedium},
		{name: "casing mistake Critical", severity: "Critical", wantErr: true},
		{name: "casing mistake HIGH", severity: "HIGH", wantErr: true},
		{name: "typo critial", severity: "critial", wantErr: true},
		{name: "unrecognized word", severity: "urgent", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			def := RuleDef{ID: "test-severity", Regex: `TEST_[A-Z0-9]{8}`, Severity: tt.severity}
			det, err := NewFromDef(def)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unrecognized severity")
				assert.Nil(t, det)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantLevel, det.Severity())
		})
	}
}

// TestParseSeverity_TableDriven directly exercises parseSeverity's five
// branches (critical/high/medium/low/default), closing the coverage gap where
// only "high" and the empty-default fallback were previously exercised.
func TestParseSeverity_TableDriven(t *testing.T) {
	tests := []struct {
		input   string
		want    finding.Severity
		wantOK  bool
		comment string
	}{
		{input: "critical", want: finding.SeverityCritical, wantOK: true},
		{input: "high", want: finding.SeverityHigh, wantOK: true},
		{input: "medium", want: finding.SeverityMedium, wantOK: true},
		{input: "low", want: finding.SeverityLow, wantOK: true},
		{input: "", want: finding.SeverityMedium, wantOK: false, comment: "empty string is not a recognized value on its own"},
		{input: "Critical", want: finding.SeverityMedium, wantOK: false},
		{input: "bogus", want: finding.SeverityMedium, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := parseSeverity(tt.input)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestRegisterCustomRules_ValidRules_RegistersAll(t *testing.T) {
	detector.Reset()
	defer detector.Reset()

	rules := []RuleDef{
		{ID: "custom-1", Regex: `CUSTOM1_[A-Z]{10}`, Keywords: []string{"CUSTOM1_"}},
		{ID: "custom-2", Regex: `CUSTOM2_[A-Z]{10}`, Keywords: []string{"CUSTOM2_"}},
	}

	count, errs := RegisterCustomRules(rules)
	assert.Equal(t, 2, count)
	assert.Empty(t, errs)

	all := detector.All()
	assert.Len(t, all, 2)
}

func TestRegisterCustomRules_MixedValidity_RegistersValidOnly(t *testing.T) {
	detector.Reset()
	defer detector.Reset()

	rules := []RuleDef{
		{ID: "valid", Regex: `VALID_[A-Z]{10}`},
		{ID: "invalid", Regex: `[unclosed`},
	}

	count, errs := RegisterCustomRules(rules)
	assert.Equal(t, 1, count)
	assert.Len(t, errs, 1)
}

func TestRegisterCustomRules_DuplicateID_SkipsWithoutPanic(t *testing.T) {
	detector.Reset()
	defer detector.Reset()

	// A custom rule whose ID collides with an already-registered detector must
	// be skipped with an error — never registered, because detector.Register
	// panics on duplicate IDs.
	first := []RuleDef{{ID: "dupe", Regex: `DUPE_[A-Z]{10}`}}
	count, errs := RegisterCustomRules(first)
	require.Equal(t, 1, count)
	require.Empty(t, errs)

	assert.NotPanics(t, func() {
		second := []RuleDef{{ID: "dupe", Regex: `OTHER_[A-Z]{10}`}}
		count, errs = RegisterCustomRules(second)
	})
	assert.Equal(t, 0, count)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "already registered")

	// Only the original detector remains registered.
	assert.Len(t, detector.All(), 1)
}

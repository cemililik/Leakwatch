package snowflake

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "snowflake-credentials", d.ID())
	assert.Equal(t, "Snowflake Connection Credentials", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidCredentials(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		password string
	}{
		{
			name:     "JDBC URL with password param",
			input:    "jdbc:snowflake://myaccount.snowflakecomputing.com:443/?db=testdb&password=secret123",
			expected: 1,
			redacted: "snowflakecomputing.com:443/?db=testdb&password=****",
			password: "secret123",
		},
		{
			name:     "JDBC URL with pwd param",
			input:    "jdbc:snowflake://myaccount.snowflakecomputing.com:443/?db=testdb&pwd=myS3cret",
			expected: 1,
			redacted: "snowflakecomputing.com:443/?db=testdb&pwd=****",
			password: "myS3cret",
		},
		{
			name:     "JDBC URL with PASSWORD uppercase",
			input:    "jdbc:snowflake://myaccount.snowflakecomputing.com:443/?db=testdb&PASSWORD=Upp3rCase",
			expected: 1,
			redacted: "snowflakecomputing.com:443/?db=testdb&PASSWORD=****",
			password: "Upp3rCase",
		},
		{
			name:     "JDBC URL with PWD uppercase",
			input:    "jdbc:snowflake://myaccount.snowflakecomputing.com:443/?db=testdb&PWD=Upp3rPwd",
			expected: 1,
			redacted: "snowflakecomputing.com:443/?db=testdb&PWD=****",
			password: "Upp3rPwd",
		},
		{
			name:     "URL with spaces around equals",
			input:    "snowflakecomputing.com?password = spaced123",
			expected: 1,
			redacted: "snowflakecomputing.com?password = ****",
			password: "spaced123",
		},
		{
			name:     "tab before equals is redacted (fail-safe)",
			input:    "snowflakecomputing.com?password\t=tabbed123",
			expected: 1,
			redacted: "snowflakecomputing.com?password\t=****",
			password: "tabbed123",
		},
		{
			name:     "double space before equals is redacted (fail-safe)",
			input:    "snowflakecomputing.com?password  =doublesp1",
			expected: 1,
			redacted: "snowflakecomputing.com?password  =****",
			password: "doublesp1",
		},
		{
			name:     "newline before equals is redacted (fail-safe)",
			input:    "snowflakecomputing.com?password\n=newline12",
			expected: 1,
			redacted: "snowflakecomputing.com?password\n=****",
			password: "newline12",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
				assert.Equal(t, tt.password, string(findings[0].Raw))
				// The raw password must NEVER be carried in ExtraData: it is
				// serialized into default (non --show-raw) output.
				assert.Empty(t, findings[0].ExtraData)
				assert.NotContains(t, findings[0].Redacted, tt.password)
			}
		})
	}
}

// TestRedactSnowflake_MasksEveryPasswordParam verifies that when a single match
// spans multiple password-family parameters (e.g. a decoy PWD followed by the
// real password), every value is masked and none survives in cleartext.
func TestRedactSnowflake_MasksEveryPasswordParam(t *testing.T) {
	input := "snowflakecomputing.com/db?PWD=decoyvalue&password=realvalue"

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(input))
	require.NotEmpty(t, findings)

	redacted := findings[0].Redacted
	assert.NotContains(t, redacted, "decoyvalue")
	assert.NotContains(t, redacted, "realvalue")
	assert.Contains(t, redacted, "PWD=****")
	assert.Contains(t, redacted, "password=****")
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "snowflake URL without password",
			input: "jdbc:snowflake://myaccount.snowflakecomputing.com:443/?db=testdb&user=admin",
		},
		{
			name:  "non-snowflake URL with password",
			input: "jdbc:mysql://host:3306/?password=secret",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

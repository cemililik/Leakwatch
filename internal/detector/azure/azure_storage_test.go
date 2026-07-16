package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &StorageDetector{}
	assert.Equal(t, "azure-storage-key", d.ID())
	assert.Equal(t, "Azure Storage Connection String", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestStorageDetector_Scan_MatchesValidConnectionString(t *testing.T) {
	// synthetic 88-char base64 account key
	accountKey88 := strings.Repeat("AbCdEfGh", 11)

	tests := []struct {
		name        string
		input       string
		expected    int
		redacted    string
		accountName string
	}{
		{
			name:        "valid https connection string",
			input:       "DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=" + accountKey88 + ";",
			expected:    1,
			redacted:    "AccountName=mystorageacct;AccountKey=****EfGh",
			accountName: "mystorageacct",
		},
		{
			name:        "valid http connection string",
			input:       "DefaultEndpointsProtocol=http;AccountName=devaccount;AccountKey=" + accountKey88 + ";",
			expected:    1,
			redacted:    "AccountName=devaccount;AccountKey=****EfGh",
			accountName: "devaccount",
		},
		{
			name:        "connection string embedded in config",
			input:       `connection_string = "DefaultEndpointsProtocol=https;AccountName=testacct;AccountKey=` + accountKey88 + `;"`,
			expected:    1,
			redacted:    "AccountName=testacct;AccountKey=****EfGh",
			accountName: "testacct",
		},
		{
			name:     "multiple connection strings",
			input:    "DefaultEndpointsProtocol=https;AccountName=acct1;AccountKey=" + accountKey88 + "; DefaultEndpointsProtocol=https;AccountName=acct2;AccountKey=" + accountKey88 + ";",
			expected: 2,
		},
	}

	d := &StorageDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
				assert.Equal(t, tt.accountName, findings[0].ExtraData["account_name"])
			}
		})
	}
}

func TestStorageDetector_Scan_Raw_DoesNotAliasInputBuffer(t *testing.T) {
	accountKey88 := strings.Repeat("AbCdEfGh", 11)
	input := []byte("DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=" + accountKey88 + ";")

	d := &StorageDetector{}
	findings := d.Scan(context.Background(), input)
	require.Len(t, findings, 1)

	raw := findings[0].Raw
	original := string(raw)

	// Mutate the caller's buffer after Scan returns; a cloned Raw must be
	// unaffected, proving it does not alias the scanned chunk's backing array.
	for i := range input {
		input[i] = 'x'
	}

	assert.Equal(t, original, string(raw))
}

func TestStorageDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "missing AccountKey",
			input: "DefaultEndpointsProtocol=https;AccountName=mystorageacct;",
		},
		{
			name:  "AccountKey too short",
			input: "DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=shortkey;",
		},
		{
			name:  "missing DefaultEndpointsProtocol",
			input: "AccountName=mystorageacct;AccountKey=" + strings.Repeat("AbCdEfGh", 11) + ";",
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

	d := &StorageDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

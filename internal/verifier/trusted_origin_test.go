package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTrustedHTTPSOrigin(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "canonical", raw: "https://provider.example", want: "https://provider.example"},
		{name: "trim and normalize host", raw: "  https://PROVIDER.Example./  ", want: "https://provider.example"},
		{name: "self managed port", raw: "https://gitlab.example:8443/", want: "https://gitlab.example:8443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeTrustedHTTPSOrigin(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	for _, raw := range []string{
		"", "provider.example", "http://provider.example", "https://provider.example/path",
		"https://provider.example?next=x", "https://provider.example/#fragment",
		"https://user:pass@provider.example", "https://*.provider.example",
		"https://localhost", "https://api.localhost", "https://127.0.0.1",
		"https://127.1", "https://0x7f000001", "https://0x7f.0x0.0x0.0x1",
		"https://provider.example:0",
		"https://provider.example:65536", "https://[::1]", "https://[fe80::1%25en0]",
	} {
		t.Run("reject_"+raw, func(t *testing.T) {
			_, err := NormalizeTrustedHTTPSOrigin(raw)
			assert.Error(t, err)
		})
	}
}

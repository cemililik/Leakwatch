package jwt

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWT_Metadata(t *testing.T) {
	d := &JWT{}
	assert.Equal(t, "jwt", d.ID())
	assert.Equal(t, "JSON Web Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestJWT_Scan_MatchesValidTokens(t *testing.T) {
	// Fake JWT: header.payload.signature (all base64url-safe characters, no real secrets)
	fakeJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid JWT",
			input:    fakeJWT,
			expected: 1,
			redacted: "****WXYZ",
		},
		{
			name:     "JWT in authorization header",
			input:    "Authorization: Bearer " + fakeJWT,
			expected: 1,
		},
		{
			name:     "JWT in JSON",
			input:    `{"token": "` + fakeJWT + `"}`,
			expected: 1,
		},
		{
			name:     "multiple JWTs",
			input:    fakeJWT + " " + fakeJWT,
			expected: 2,
		},
		{
			name:     "JWT in large text",
			input:    strings.Repeat("a", 10000) + fakeJWT + strings.Repeat("b", 10000),
			expected: 1,
		},
	}

	d := &JWT{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

// TestJWT_Scan_SuppressesGitHubStatelessTokenBody verifies that the JWT body of
// a GitHub stateless installation token (ghs_APPID_<jwt>) is NOT reported by the
// jwt detector: that whole token is already reported by github-oauth-token, so
// emitting the embedded JWT too would split one secret into two findings.
func TestJWT_Scan_SuppressesGitHubStatelessTokenBody(t *testing.T) {
	// header/payload are the well-known jwt.io example segments (base64url of
	// {"alg":"HS256"} and {"sub":"1234567890"}) so the body is structurally
	// valid and survives the detector's JSON-shape check; the signature is an
	// arbitrary fake run (never decoded/validated).
	header := "eyJhbGciOiJIUzI1NiJ9"
	payload := "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	signature := strings.Repeat("Mn3Op4Qr", 12)
	jwtBody := header + "." + payload + "." + signature
	statelessToken := "ghs_12345678_" + jwtBody

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "stateless ghs_ token body is suppressed",
			input:    statelessToken,
			expected: 0,
		},
		{
			name:     "stateless token embedded in config is suppressed",
			input:    "GITHUB_TOKEN=" + statelessToken + "\n",
			expected: 0,
		},
		{
			// A base64url char glued directly before "ghs_" (no delimiter) must
			// still be recognised as a ghs_ body: the github-oauth-token detector
			// matches "ghs_..." mid-string, so reporting the JWT too would double
			// the same secret.
			name:     "stateless token glued to a preceding token char is suppressed",
			input:    "x" + statelessToken,
			expected: 0,
		},
		{
			name:     "standalone JWT is still reported",
			input:    jwtBody,
			expected: 1,
		},
		{
			name:     "JWT preceded by a non-ghs token run is still reported",
			input:    "Bearer " + jwtBody,
			expected: 1,
		},
		{
			name:     "stateless token plus an unrelated standalone JWT",
			input:    statelessToken + " and also " + jwtBody,
			expected: 1,
		},
	}

	d := &JWT{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
		})
	}
}

func TestJWT_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "only header part",
			input: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			name:  "two parts only",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
		},
		{
			name:  "short signature",
			input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.short",
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

	d := &JWT{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

// TestJWT_Scan_RejectsStructurallyInvalidMatches verifies that a
// regex-shaped-but-not-actually-a-JWT match (three dot-separated base64url
// segments whose first two merely happen to start with the literal "eyJ"
// prefix, plausible in webpack/source-map hashes or other base64 data at
// scale) is never reported, since it does not decode to valid JSON.
func TestJWT_Scan_RejectsStructurallyInvalidMatches(t *testing.T) {
	notJWT := "eyJ" + strings.Repeat("Ab9Cd0Ef", 5) + "." +
		"eyJ" + strings.Repeat("Gh1Ij2Kl", 5) + "." +
		strings.Repeat("Mn3Op4Qr", 5)

	d := &JWT{}
	findings := d.Scan(context.Background(), []byte(notJWT))
	assert.Empty(t, findings, "regex-shaped but non-JSON segments must not be reported as a JWT")
}

// TestJWT_Scan_RejectsHeaderWithoutAlg verifies that a header which decodes to
// valid JSON but lacks the "alg" key every real JWT header carries (RFC 7519
// §5.1) is not reported.
func TestJWT_Scan_RejectsHeaderWithoutAlg(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"foo":"bar1234567890"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890"}`))
	input := header + "." + payload + "." + strings.Repeat("Mn3Op4Qr", 5)

	d := &JWT{}
	findings := d.Scan(context.Background(), []byte(input))
	assert.Empty(t, findings, "header JSON without an alg key must not be reported as a JWT")
}

// TestJWT_Scan_RawIsClonedNotAliased verifies Raw does not alias the scanned
// chunk buffer, so the buffer is GC-eligible once Scan returns rather than
// pinned for the whole scan (memory/aliasing hardening).
func TestJWT_Scan_RawIsClonedNotAliased(t *testing.T) {
	fakeJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	data := []byte(fakeJWT)

	d := &JWT{}
	findings := d.Scan(context.Background(), data)
	require.Len(t, findings, 1)

	// Mutate the original buffer after Scan returns; a cloned Raw must be
	// unaffected, whereas an aliased Raw would observe the mutation.
	rawBefore := string(findings[0].Raw)
	for i := range data {
		data[i] = 'x'
	}
	assert.Equal(t, rawBefore, string(findings[0].Raw), "Raw must be a clone, not an alias of the scanned buffer")
}

// TestIsStructurallyValidJWT_TableDriven exercises the structural validation
// helper directly against well-formed, malformed, and adversarial
// (truncated/non-JSON/wrong-shape) segments.
func TestIsStructurallyValidJWT_TableDriven(t *testing.T) {
	validHeader := "eyJhbGciOiJIUzI1NiJ9"         // {"alg":"HS256"}
	validPayload := "eyJzdWIiOiIxMjM0NTY3ODkwIn0" // {"sub":"1234567890"}
	noAlgHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	arrayHeader := base64.RawURLEncoding.EncodeToString([]byte(`["alg","HS256"]`))
	notJSONPayload := base64.RawURLEncoding.EncodeToString([]byte(`not json`))

	tests := []struct {
		name  string
		match string
		want  bool
	}{
		{"valid header and payload", validHeader + "." + validPayload + "." + "sig1234567890", true},
		{"header missing alg key", noAlgHeader + "." + validPayload + "." + "sig1234567890", false},
		{"header not valid base64", "eyJ***not-base64***" + "." + validPayload + "." + "sig1234567890", false},
		{"header decodes to a JSON array, not an object", arrayHeader + "." + validPayload + "." + "sig1234567890", false},
		{"payload is not valid JSON", validHeader + "." + notJSONPayload + "." + "sig1234567890", false},
		{"only two segments", validHeader + "." + validPayload, false},
		{"empty match", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isStructurallyValidJWT([]byte(tt.match)))
		})
	}
}

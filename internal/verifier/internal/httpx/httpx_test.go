package httpx

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactError_ReplacesSecret(t *testing.T) {
	// fakeSecret is a non-secret placeholder used only to prove redaction.
	const fakeSecret = "FAKEtoken1234567890"

	tests := []struct {
		name        string
		err         error
		secret      string
		wantContain string
		wantAbsent  string
	}{
		{
			name:        "secret embedded in url error is redacted",
			err:         errors.New(`Get "https://api.example.com/bot` + fakeSecret + `/getMe": dial tcp: lookup failed`),
			secret:      fakeSecret,
			wantContain: "[REDACTED]",
			wantAbsent:  fakeSecret,
		},
		{
			name:        "secret appearing multiple times is fully redacted",
			err:         errors.New(fakeSecret + " then again " + fakeSecret),
			secret:      fakeSecret,
			wantContain: "[REDACTED] then again [REDACTED]",
			wantAbsent:  fakeSecret,
		},
		{
			name:        "no secret present leaves message intact",
			err:         errors.New("dial tcp: connection refused"),
			secret:      fakeSecret,
			wantContain: "dial tcp: connection refused",
			wantAbsent:  fakeSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactError(tt.err, tt.secret)
			assert.Contains(t, got, tt.wantContain)
			assert.NotContains(t, got, tt.wantAbsent)
		})
	}
}

func TestRedactError_URLEncodedSecret_IsRedacted(t *testing.T) {
	// A secret containing URL-reserved characters is percent-encoded by net/url
	// when embedded in a request path, so the transformed form is what surfaces
	// in a transport error. Redaction must still strip it fully.
	const rawSecret = "ab/cd ef?gh" // contains reserved chars: '/', ' ', '?'
	encoded := url.PathEscape(rawSecret)
	require.NotEqual(t, rawSecret, encoded, "test secret must actually be transformed")

	err := errors.New(`Get "https://api.example.com/v1/` + encoded + `": dial tcp: lookup failed`)
	got := RedactError(err, rawSecret)

	assert.Contains(t, got, "[REDACTED]")
	assert.NotContains(t, got, encoded, "the percent-encoded secret must not survive redaction")
}

func TestClient_TLSMinVersion_IsTLS12(t *testing.T) {
	c := Client()
	tr, ok := c.Transport.(*http.Transport)
	require.True(t, ok, "shared client transport should be an *http.Transport")
	require.NotNil(t, tr.TLSClientConfig, "TLS config should be set explicitly")
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
}

func TestClient_NoWallClockTimeout(t *testing.T) {
	// The shared client relies solely on the per-request context deadline, so it
	// must not impose an http.Client.Timeout that could silently cap a higher
	// operator-configured verification timeout.
	assert.Zero(t, Client().Timeout)
}

func TestRedactError_EmptySecret_ReturnsOriginal(t *testing.T) {
	err := errors.New("some transport error")
	assert.Equal(t, "some transport error", RedactError(err, ""))
}

func TestRedactError_NilError_ReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", RedactError(nil, "anything"))
}

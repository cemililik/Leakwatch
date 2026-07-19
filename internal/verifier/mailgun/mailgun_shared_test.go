package mailgun

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "mailgun",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			// euAPIURL is pointed at the same test server so a test case that
			// happens to report the US probe inactive never triggers a real
			// network call to the live EU host.
			return &Verifier{apiURL: apiURL, euAPIURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("key-abcdef1234567890abcdef1234567890"),
			Redacted:   "key-****7890",
		},
		// The Mailgun verifier checks only the status code on success.
		SkipMalformed: true,
	})
}

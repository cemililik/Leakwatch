package twilio

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{Name: "twilio", New: func(url string, client *http.Client) verifier.Verifier {
		return &Verifier{apiURL: url, httpClient: client}
	}, Raw: detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("SyntheticTwilioAPIKeySecretFixture"),
		ExtraData:  map[string]string{"api_key_sid": "SKabcdef0123456789abcdef0123456789"},
	}})
}

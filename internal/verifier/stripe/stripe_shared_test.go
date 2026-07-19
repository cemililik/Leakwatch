package stripe

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestLiveVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "stripe-live",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &LiveKeyVerifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: liveDetectorID,
			Raw:        []byte("sk_live_abcdef1234567890abcdef12"),
			Redacted:   "sk_live_****ef12",
		},
	})
}

func TestTestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "stripe-test",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &TestKeyVerifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: testDetectorID,
			Raw:        []byte("sk_test_abcdef1234567890abcdef12"),
			Redacted:   "sk_test_****ef12",
		},
	})
}

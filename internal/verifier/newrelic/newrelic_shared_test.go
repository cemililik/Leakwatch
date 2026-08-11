package newrelic

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "newrelic",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &Verifier{endpoints: []endpoint{{region: "test", url: apiURL}}, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte(testToken),
			Redacted:   "NRAK-****2MNO",
		},
	})
}

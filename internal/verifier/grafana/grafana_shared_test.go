package grafana

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "grafana",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &Verifier{instanceURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("glsa_sharedsafetyfixture12345678901234567_12345678"),
			Redacted:   "glsa_****5678",
		},
	})
}

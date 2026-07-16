package dockerhub

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "dockerhub",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &Verifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("dckr_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"),
			Redacted:   "dckr_pat_****cdef",
		},
	})
}

package sonarcloud

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{Name: "sonarcloud", New: func(url string, client *http.Client) verifier.Verifier {
		return &Verifier{apiURL: url, httpClient: client}
	}, Raw: detector.RawFinding{DetectorID: detectorID, Raw: []byte("sqp_abcdef0123456789abcdef0123456789abcdef01")}})
}

package cloudflare

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{Name: "cloudflare", New: func(url string, client *http.Client) verifier.Verifier {
		return &Verifier{apiURL: url, httpClient: client}
	}, Raw: detector.RawFinding{DetectorID: detectorID, Raw: []byte("SyntheticCloudflareTokenFixture123456")}})
}

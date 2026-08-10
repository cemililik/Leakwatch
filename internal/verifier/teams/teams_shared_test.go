package teams

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "teams",
		New: func(_ string, client *http.Client) verifier.Verifier {
			return &Verifier{httpClient: client}
		},
		RawForURL: func(endpoint string) detector.RawFinding {
			return detector.RawFinding{DetectorID: detectorID, Raw: []byte(endpoint), Redacted: "https://teams.invalid/****"}
		},
		SkipMalformed: true,
	})
}

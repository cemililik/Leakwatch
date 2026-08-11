package meta

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const providerLinkCheckEnvironment = "LEAKWATCH_CHECK_PROVIDER_LINKS"

var officialProviderDocumentationHosts = map[string]struct{}{
	"api.slack.com":      {},
	"auth0.com":          {},
	"docs.datadoghq.com": {},
	"docs.github.com":    {},
	"docs.gitlab.com":    {},
	"docs.newrelic.com":  {},
	"docs.slack.dev":     {},
	"docs.snyk.io":       {},
	"github.blog":        {},
	"grafana.com":        {},
	"shopify.dev":        {},
	"supabase.com":       {},
	"www.twilio.com":     {},
}

func isOfficialProviderDocumentationURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	_, ok := officialProviderDocumentationHosts[strings.ToLower(parsed.Hostname())]
	return ok
}

func TestVerificationCapabilities_ReferencesUseOfficialProviderHosts(t *testing.T) {
	for _, capability := range VerificationCapabilities() {
		for _, reference := range capability.ContractReferenceURLs {
			assert.True(t, isOfficialProviderDocumentationURL(reference), "%s: %s", capability.DetectorID, reference)
		}
	}
	assert.False(t, isOfficialProviderDocumentationURL("https://docs.gitlab.com.attacker.example/api/users/"))
	assert.False(t, isOfficialProviderDocumentationURL("http://docs.gitlab.com/api/users/"))
}

func TestVerificationCapabilities_CriticalReferencesMatchImplementedEndpoints(t *testing.T) {
	byDetector := make(map[string][]string)
	for _, capability := range VerificationCapabilities() {
		byDetector[capability.DetectorID] = capability.ContractReferenceURLs
	}
	assert.Contains(t, byDetector["gitlab-pat"], "https://docs.gitlab.com/api/users/#retrieve-the-current-user")
	assert.Contains(t, byDetector["gitlab-pat"], "https://docs.gitlab.com/api/personal_access_tokens/")
	assert.Contains(t, byDetector["github-oauth-token"], "https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation")
}

func TestVerificationCapabilities_ReviewedReferenceLinksResolve(t *testing.T) {
	if os.Getenv(providerLinkCheckEnvironment) != "1" {
		t.Skip("network contract audit is enabled only by the protected scheduled workflow")
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("provider documentation redirect limit exceeded")
			}
			if !isOfficialProviderDocumentationURL(request.URL.String()) {
				return fmt.Errorf("provider documentation redirected outside official hosts")
			}
			return nil
		},
	}

	seen := make(map[string]struct{})
	var references []string
	for _, capability := range VerificationCapabilities() {
		for _, reference := range capability.ContractReferenceURLs {
			if _, exists := seen[reference]; !exists {
				seen[reference] = struct{}{}
				references = append(references, reference)
			}
		}
	}
	sort.Strings(references)
	for _, reference := range references {
		t.Run(reference, func(t *testing.T) {
			parsed, err := url.Parse(reference)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, reference, nil)
			require.NoError(t, err)
			request.Header.Set("User-Agent", "leakwatch-provider-contract-audit")
			response, err := client.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			require.GreaterOrEqual(t, response.StatusCode, http.StatusOK)
			require.Less(t, response.StatusCode, http.StatusMultipleChoices)

			body, err := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
			require.NoError(t, err)
			require.LessOrEqual(t, len(body), 8*1024*1024, "provider documentation response exceeds audit bound")
			if parsed.Fragment == "" {
				return
			}
			fragment, err := url.PathUnescape(parsed.Fragment)
			require.NoError(t, err)
			fragmentPattern := regexp.MustCompile(`(?i)\bid=(?:"` + regexp.QuoteMeta(fragment) + `"|'` + regexp.QuoteMeta(fragment) + `'|` + regexp.QuoteMeta(fragment) + `(?:[ >]))`)
			require.True(t, fragmentPattern.Match(body),
				"fragment %q is absent from provider documentation", fragment)
		})
	}
}

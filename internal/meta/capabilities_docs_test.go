package meta

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	markdownDetectorRow = regexp.MustCompile("^\\| `([^`]+)` \\|")
	siteCapabilityRow   = regexp.MustCompile(`(?s)<div class="vrow">.*?data-i18n="verify\.(live|context|fmt|no)\.k".*?<span class="vcount">(\d+)</span>.*?</div>`)
	siteStatCell        = regexp.MustCompile(`(?s)<div class="cell"><div class="n"><b>(\d+)</b></div><div class="l" data-i18n="stats\.(detectors|verifiers|sources|formats)">`)
)

type documentedCategory struct {
	heading string
	kind    VerifierKind
}

func TestVerificationCoverageDocs_MatchCapabilityManifest(t *testing.T) {
	counts := VerificationCapabilityCounts()
	tests := []struct {
		name       string
		path       string
		categories []documentedCategory
		summary    []string
	}{
		{
			name: "English",
			path: filepath.Join("..", "..", "docs", "user-manuals", "en", "verification", "verification-coverage.md"),
			categories: []documentedCategory{
				{heading: "## Live-verified", kind: VerifierLive},
				{heading: "## Requires trusted or companion context", kind: VerifierRequiresContext},
				{heading: "## Format-validated only", kind: VerifierFormatOnly},
				{heading: "## Not verifiable", kind: VerifierNone},
			},
			summary: []string{
				fmt.Sprintf("| Live-verified | %d |", counts.Live),
				fmt.Sprintf("| Requires trusted/companion context | %d |", counts.RequiresContext),
				fmt.Sprintf("| Format-validated only | %d |", counts.FormatOnly),
				fmt.Sprintf("| Not verifiable | %d |", counts.None),
				fmt.Sprintf("| **Total detectors** | **%d** |", Detectors),
			},
		},
		{
			name: "Turkish",
			path: filepath.Join("..", "..", "docs", "user-manuals", "tr", "verification", "verification-coverage.md"),
			categories: []documentedCategory{
				{heading: "## Canlı doğrulanan", kind: VerifierLive},
				{heading: "## Güvenilir veya eşlik eden bağlam gerektiren", kind: VerifierRequiresContext},
				{heading: "## Yalnızca format doğrulaması", kind: VerifierFormatOnly},
				{heading: "## Doğrulanamaz", kind: VerifierNone},
			},
			summary: []string{
				fmt.Sprintf("| Canlı doğrulanan | %d |", counts.Live),
				fmt.Sprintf("| Güvenilir/eşlik eden bağlam gerektiren | %d |", counts.RequiresContext),
				fmt.Sprintf("| Yalnızca format doğrulaması | %d |", counts.FormatOnly),
				fmt.Sprintf("| Doğrulanamaz | %d |", counts.None),
				fmt.Sprintf("| **Toplam dedektör** | **%d** |", Detectors),
			},
		},
	}

	want := make(map[string]VerifierKind, Detectors)
	for _, capability := range VerificationCapabilities() {
		want[capability.DetectorID] = capability.VerifierKind
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contents, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			got := parseDocumentedCapabilities(t, string(contents), tc.categories)
			assert.Equal(t, want, got, "documentation categories drifted from capability manifest")
			for _, summary := range tc.summary {
				assert.Contains(t, string(contents), summary)
			}
		})
	}
}

func TestPublishedCapabilityClaims_MatchManifest(t *testing.T) {
	counts := VerificationCapabilityCounts()
	require.Equal(t, CapabilityCounts{Live: 41, FormatOnly: 6, RequiresContext: 7, None: 11}, counts)
	registryCoverage := 100 * float64(Verifiers) / float64(Detectors)

	tests := []struct {
		path     string
		required []string
		forbid   []string
	}{
		{
			path: filepath.Join("..", "..", "README.md"),
			required: []string{
				fmt.Sprintf("**%d built-in detectors**", Detectors),
				fmt.Sprintf("**%d direct live checks** + **%d context-required checks** + **%d offline format validators**", counts.Live, counts.RequiresContext, counts.FormatOnly),
				fmt.Sprintf("**%d of %d detectors (%.1f%%)**", Verifiers, Detectors, registryCoverage),
			},
			forbid: []string{"54 live verifiers", "54 verifiers, 84.4%", "~48 detectors"},
		},
		{
			path: filepath.Join("..", "..", "site", "index.html"),
			required: []string{
				fmt.Sprintf("%d detectors · %d direct-live · %d context-required · %d sources", Detectors, counts.Live, counts.RequiresContext, Sources),
				fmt.Sprintf(`<span class="vcount">%d</span>`, counts.Live),
				fmt.Sprintf(`<span class="vcount">%d</span>`, counts.RequiresContext),
				fmt.Sprintf(`<span class="vcount">%d</span>`, counts.FormatOnly),
				fmt.Sprintf(`<span class="vcount">%d</span>`, counts.None),
			},
			forbid: []string{"54 live verifiers", "~49", "Redacted index — 64 detectors"},
		},
		{
			path: filepath.Join("..", "..", "site", "js", "translations.js"),
			required: []string{
				fmt.Sprintf(`"hero.kv": "%d detectors · %d direct-live · %d context-required · %d sources"`, Detectors, counts.Live, counts.RequiresContext, Sources),
				fmt.Sprintf(`"hero.kv": "%d dedektör · %d doğrudan canlı · %d bağlam gerektiren · %d kaynak"`, Detectors, counts.Live, counts.RequiresContext, Sources),
			},
			forbid: []string{"54 live verifiers", "54 canlı doğrulayıcı", "64 detectors", "63 dedektör"},
		},
		{
			path: filepath.Join("..", "..", "docs", "guides", "secret-verification.md"),
			required: []string{
				fmt.Sprintf("**%d** detectors support a direct live check", counts.Live),
				fmt.Sprintf("**%d** require trusted issuer, region, or companion context", counts.RequiresContext),
				fmt.Sprintf("### Not Verifiable (%d detectors)", counts.None),
			},
			forbid: []string{"Live API Verification (48 detectors)", "84.4% of its 64 detectors"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			contents, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			text := string(contents)
			for _, required := range tc.required {
				assert.Contains(t, text, required)
			}
			for _, forbidden := range tc.forbid {
				assert.NotContains(t, text, forbidden)
			}
		})
	}
}

func TestSiteVisibleCounts_MatchCapabilityManifest(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "site", "index.html"))
	require.NoError(t, err)
	counts := VerificationCapabilityCounts()

	wantCapabilities := map[string]int{
		"live": counts.Live, "context": counts.RequiresContext,
		"fmt": counts.FormatOnly, "no": counts.None,
	}
	gotCapabilities := make(map[string]int, len(wantCapabilities))
	for _, match := range siteCapabilityRow.FindAllStringSubmatch(string(contents), -1) {
		var count int
		_, err := fmt.Sscanf(match[2], "%d", &count)
		require.NoError(t, err)
		gotCapabilities[match[1]] = count
	}
	assert.Equal(t, wantCapabilities, gotCapabilities)

	wantStats := map[string]int{
		"detectors": Detectors, "verifiers": counts.Live,
		"sources": Sources, "formats": OutputFormats,
	}
	gotStats := make(map[string]int, len(wantStats))
	for _, match := range siteStatCell.FindAllStringSubmatch(string(contents), -1) {
		var count int
		_, err := fmt.Sscanf(match[1], "%d", &count)
		require.NoError(t, err)
		gotStats[match[2]] = count
	}
	assert.Equal(t, wantStats, gotStats)
}

func parseDocumentedCapabilities(
	t *testing.T,
	contents string,
	categories []documentedCategory,
) map[string]VerifierKind {
	t.Helper()
	headingKinds := make(map[string]VerifierKind, len(categories))
	for _, category := range categories {
		headingKinds[category.heading] = category.kind
	}

	got := make(map[string]VerifierKind, Detectors)
	current := VerifierKind("")
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "## ") {
			current = ""
			for heading, kind := range headingKinds {
				if strings.HasPrefix(line, heading) {
					current = kind
					break
				}
			}
			continue
		}
		if current == "" {
			continue
		}
		match := markdownDetectorRow.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if previous, duplicate := got[match[1]]; duplicate {
			t.Errorf("detector %q documented twice (%s and %s)", match[1], previous, current)
		}
		got[match[1]] = current
	}
	require.NoError(t, scanner.Err())
	return got
}

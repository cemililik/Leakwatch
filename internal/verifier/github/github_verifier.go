// Package github provides a verifier for GitHub personal access tokens.
// It uses the GitHub API GET /user endpoint to check token validity.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "github-token"

// Verifier checks whether a GitHub token is active by calling the
// GitHub API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL is reserved for a validated, trusted GitHub.com or GHES API
	// origin. The production registration leaves it empty until operator wiring
	// exists; tests inject a local server.
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

// NewForTrustedInstance constructs a GitHub PAT verifier for an origin chosen
// explicitly by the operator (GitHub.com API or a GHES API origin).
func NewForTrustedInstance(instanceURL string) (*Verifier, error) {
	normalized, err := verifier.NormalizeTrustedHTTPSOrigin(instanceURL)
	if err != nil {
		return nil, err
	}
	return &Verifier{apiURL: normalized}, nil
}

// WithTrustedInstance implements verifier.TrustedInstanceConfigurer.
func (*Verifier) WithTrustedInstance(instanceURL string) (verifier.Verifier, error) {
	return NewForTrustedInstance(instanceURL)
}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify checks if the detected GitHub token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted GitHub API origin is not configured",
		}
	}
	apiURL := v.apiURL

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "github",
		Request: httpx.Request{
			URL: apiURL + "/user",
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Accept":        "application/vnd.github+json",
			},
		},
		ActiveMessage:          "GitHub token is active",
		InactiveMessage:        "GitHub token is invalid or revoked",
		DecodeResponse:         decodeUserResponse,
		DecodeInactive:         decodeGitHubInactive,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
}

func decodeGitHubInactive(body io.Reader) error {
	var response struct {
		Message string `json:"message"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&response); err != nil {
		return err
	}
	if strings.TrimSpace(response.Message) != "Bad credentials" {
		return fmt.Errorf("unexpected GitHub authentication error")
	}
	return requireGitHubJSONEOF(decoder)
}

// decodeUserResponse parses the required identity body and enriches classic PAT
// findings with the provider's documented OAuth-scope and token-expiry response
// headers. Fine-grained tokens may omit X-OAuth-Scopes; absence is not an error.
func decodeUserResponse(header http.Header, body io.Reader) (map[string]string, string, error) {
	extra, downgrade, err := decodeUser(body)
	if err != nil {
		return nil, "", err
	}
	if scopes := normalizedScopes(header.Get("X-OAuth-Scopes")); len(scopes) > 0 {
		extra["scopes"] = strings.Join(scopes, ",")
		extra["scope_count"] = strconv.Itoa(len(scopes))
	}
	if expiresAt, ok := normalizedGitHubExpiry(header.Get("GitHub-Authentication-Token-Expiration")); ok {
		extra["expires_at"] = expiresAt
	}
	return extra, downgrade, nil
}

// decodeUser parses the GitHub API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Login string `json:"login"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&user); err != nil {
		return nil, "", err
	}
	user.Login = strings.TrimSpace(user.Login)
	if user.Login == "" {
		return nil, "", fmt.Errorf("missing GitHub user login")
	}
	if err := requireGitHubJSONEOF(decoder); err != nil {
		return nil, "", err
	}
	return map[string]string{"login": user.Login}, "", nil
}

func requireGitHubJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("GitHub response contains trailing JSON values")
		}
		return fmt.Errorf("invalid trailing GitHub response: %w", err)
	}
	return nil
}

func normalizedScopes(raw string) []string {
	if len(raw) > 4096 {
		return nil
	}
	seen := make(map[string]struct{})
	for _, candidate := range strings.Split(raw, ",") {
		scope := strings.TrimSpace(candidate)
		if scope == "" || len(scope) > 64 || !isSafeScope(scope) {
			continue
		}
		seen[scope] = struct{}{}
		if len(seen) >= 128 {
			break
		}
	}
	scopes := make([]string, 0, len(seen))
	for scope := range seen {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	return scopes
}

func isSafeScope(scope string) bool {
	for _, char := range scope {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ':' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func normalizedGitHubExpiry(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05 MST"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC().Format(time.RFC3339), true
		}
	}
	return "", false
}

// Package gitlab provides a verifier for GitLab personal access tokens.
// It uses the GitLab API GET /api/v4/user endpoint to check token validity.
package gitlab

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

const detectorID = "gitlab-pat"

type gitLabGranularScope struct {
	Access      string   `json:"access"`
	Permissions []string `json:"permissions"`
	ProjectID   *int64   `json:"project_id"`
	GroupID     *int64   `json:"group_id"`
}

// Verifier checks whether a GitLab personal access token is active by calling
// the GitLab API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the GitLab API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

var _ verifier.RequestGatedVerifier = (*Verifier)(nil)

// NewForTrustedInstance constructs a GitLab verifier for an API origin
// explicitly supplied by the operator. Finding metadata and scanned URLs are
// deliberately never accepted as routing authority.
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

// VerificationRequestBudget covers the identity probe, the optional PAT
// self-metadata probe, and at most one bounded 429 retry for each GET.
func (*Verifier) VerificationRequestBudget() int { return 4 }

// Verify checks if the detected GitLab personal access token is valid/active.
// Raw contains the token value. Only personal access tokens (`glpat-`) can use
// the read-only `/user` probe. Other GitLab credential families have different
// authentication contracts and remain unverified.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return v.verify(ctx, raw, nil)
}

// VerifyWithRequestGate admits every actual identity/metadata request (and any
// bounded GET retry) at its send point.
func (v *Verifier) VerifyWithRequestGate(
	ctx context.Context,
	raw detector.RawFinding,
	gate verifier.RequestGate,
) finding.VerificationResult {
	return v.verify(ctx, raw, gate)
}

func (v *Verifier) verify(
	ctx context.Context,
	raw detector.RawFinding,
	gate verifier.RequestGate,
) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{Status: finding.StatusUnverified, Message: "empty token"}
	}
	if !strings.HasPrefix(token, "glpat-") {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "GitLab token subtype has no safe universal verification probe",
		}
	}
	if v.apiURL == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "trusted GitLab API origin is not configured",
		}
	}
	if rejection := admitGitLabRequest(gate); rejection != nil {
		return *rejection
	}
	requestCtx := ctx
	if gate != nil {
		requestCtx = httpx.WithRetryGate(ctx, httpx.RetryGate(gate))
	}

	result := httpx.VerifyToken(requestCtx, v.httpClient, token, httpx.TokenSpec{
		Name: "gitlab",
		Request: httpx.Request{
			URL:    v.apiURL + "/api/v4/user",
			Header: map[string]string{"PRIVATE-TOKEN": token},
		},
		ActiveMessage:          "GitLab token is active",
		InactiveMessage:        "GitLab token is invalid or revoked",
		Decode:                 decodeUser,
		DecodeInactive:         decodeUnauthorized,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
	if result.Status != finding.StatusVerifiedActive {
		return result
	}

	// Token metadata is optional enrichment. Older/self-managed instances and
	// non-personal glpat token families may not expose the PAT self endpoint;
	// the proven-active /user result remains authoritative in those cases.
	if rejection := admitGitLabRequest(gate); rejection != nil {
		return result
	}
	metadata := httpx.VerifyToken(requestCtx, v.httpClient, token, httpx.TokenSpec{
		Name: "gitlab-token-metadata",
		Request: httpx.Request{
			URL:    v.apiURL + "/api/v4/personal_access_tokens/self",
			Header: map[string]string{"PRIVATE-TOKEN": token},
		},
		ActiveMessage:          "GitLab token metadata is available",
		InactiveMessage:        "GitLab token metadata is unavailable",
		Decode:                 decodeTokenMetadata,
		RequireCompleteBody:    true,
		RequireJSONContentType: true,
	})
	if metadata.Status == finding.StatusVerifiedActive {
		if result.ExtraData == nil {
			result.ExtraData = make(map[string]string)
		}
		for key, value := range metadata.ExtraData {
			result.ExtraData[key] = value
		}
	}
	return result
}

func admitGitLabRequest(gate verifier.RequestGate) *finding.VerificationResult {
	if gate == nil {
		return nil
	}
	return gate()
}

// decodeUser parses the GitLab API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&user); err != nil {
		return nil, "", err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, "", err
	}
	if user.ID <= 0 || strings.TrimSpace(user.Username) == "" {
		return nil, "", fmt.Errorf("GitLab user response is missing required identity fields")
	}
	return map[string]string{"username": user.Username}, "", nil
}

func decodeUnauthorized(body io.Reader) error {
	var response struct {
		Message string `json:"message"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&response); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	if response.Message != "401 Unauthorized" {
		return fmt.Errorf("GitLab response is not a standard invalid-token response")
	}
	return nil
}

func decodeTokenMetadata(body io.Reader) (map[string]string, string, error) {
	var metadata struct {
		Active         bool                  `json:"active"`
		Revoked        bool                  `json:"revoked"`
		Scopes         []string              `json:"scopes"`
		GranularScopes []gitLabGranularScope `json:"granular_scopes"`
		ExpiresAt      *string               `json:"expires_at"`
	}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&metadata); err != nil {
		return nil, "", err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, "", err
	}
	if !metadata.Active || metadata.Revoked {
		return nil, "", fmt.Errorf("GitLab self metadata did not describe an active token")
	}
	extra := make(map[string]string)
	scopes, err := normalizedTokenScopes(metadata.Scopes, metadata.GranularScopes)
	if err != nil {
		return nil, "", err
	}
	if len(scopes) > 0 {
		extra["scopes"] = strings.Join(scopes, ",")
		extra["scope_count"] = strconv.Itoa(len(scopes))
	}
	if metadata.ExpiresAt != nil && strings.TrimSpace(*metadata.ExpiresAt) != "" {
		expiresAt := strings.TrimSpace(*metadata.ExpiresAt)
		if _, err := time.Parse(time.DateOnly, expiresAt); err != nil {
			return nil, "", fmt.Errorf("GitLab token expiry is not an ISO date")
		}
		extra["expires_at"] = expiresAt
	}
	return extra, "", nil
}

func normalizedTokenScopes(standard []string, granular []gitLabGranularScope) ([]string, error) {
	result := normalizedMetadataScopes(standard)
	if len(granular) > 128 {
		return nil, fmt.Errorf("GitLab granular scope list exceeds safe limit")
	}
	seen := make(map[string]struct{}, len(result)+len(granular))
	for _, scope := range result {
		seen[scope] = struct{}{}
	}
	for _, scope := range granular {
		access := strings.TrimSpace(scope.Access)
		if !isAllowedGranularAccess(access) || len(scope.Permissions) == 0 || len(scope.Permissions) > 128 {
			return nil, fmt.Errorf("GitLab granular scope has an invalid access contract")
		}
		target := ""
		if access == "selected_memberships" {
			switch {
			case scope.ProjectID != nil && *scope.ProjectID > 0 && scope.GroupID == nil:
				target = ":project:" + strconv.FormatInt(*scope.ProjectID, 10)
			case scope.GroupID != nil && *scope.GroupID > 0 && scope.ProjectID == nil:
				target = ":group:" + strconv.FormatInt(*scope.GroupID, 10)
			default:
				return nil, fmt.Errorf("GitLab selected-membership scope has an invalid target")
			}
		} else if scope.ProjectID != nil || scope.GroupID != nil {
			return nil, fmt.Errorf("GitLab granular scope has an unexpected membership target")
		}
		for _, candidate := range scope.Permissions {
			permission := strings.TrimSpace(candidate)
			if permission == "" || len(permission) > 64 || !isSafeMetadataScope(permission) {
				return nil, fmt.Errorf("GitLab granular scope has an invalid permission")
			}
			label := "granular:" + access + target + ":" + permission
			seen[label] = struct{}{}
			if len(seen) > 128 {
				return nil, fmt.Errorf("GitLab normalized scope list exceeds safe limit")
			}
		}
	}
	result = result[:0]
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result, nil
}

func isAllowedGranularAccess(access string) bool {
	switch access {
	case "selected_memberships", "user", "instance", "all_memberships", "personal_projects":
		return true
	default:
		return false
	}
}

func normalizedMetadataScopes(input []string) []string {
	seen := make(map[string]struct{})
	for _, candidate := range input {
		scope := strings.TrimSpace(candidate)
		if scope == "" || len(scope) > 64 || !isSafeMetadataScope(scope) {
			continue
		}
		seen[scope] = struct{}{}
		if len(seen) >= 128 {
			break
		}
	}
	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func isSafeMetadataScope(scope string) bool {
	for _, char := range scope {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ':' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("response contains trailing JSON values")
		}
		return err
	}
	return nil
}

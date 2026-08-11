// Package aws provides a verifier for AWS Access Key credentials.
// It uses AWS STS GetCallerIdentity to check whether a key pair is active.
package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "aws-access-key-id"

// stsClient abstracts the STS API for testing.
type stsClient interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Verifier checks whether an AWS access key pair is active by calling
// STS GetCallerIdentity. It NEVER logs or persists raw key values.
type Verifier struct {
	client stsClient
}

var _ verifier.RequestGatedVerifier = (*Verifier)(nil)

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify checks if the detected AWS access key is valid/active.
// Raw contains the Access Key ID and RawV2 contains the Secret Access Key.
// Both are required for verification.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return v.verify(ctx, raw, nil)
}

// VerificationRequestBudget declares the single STS probe this verifier can
// issue for a complete key pair.
func (v *Verifier) VerificationRequestBudget() int { return 1 }

// VerifyWithRequestGate admits the STS request at its actual SDK send point.
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
	if len(raw.RawV2) == 0 {
		slog.DebugContext(ctx, "aws verifier: secret access key not found, skipping verification")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "secret access key not found",
		}
	}

	client := v.client
	if client == nil {
		client = sts.New(sts.Options{
			Region: "us-east-1",
			Credentials: credentials.NewStaticCredentialsProvider(
				string(raw.Raw),
				string(raw.RawV2),
				"",
			),
		})
	}
	if gate != nil {
		if rejection := gate(); rejection != nil {
			return *rejection
		}
	}

	output, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		// Check if this is an authentication error (invalid credentials).
		// AWS returns specific error codes for invalid/expired keys.
		if isAuthError(err) {
			slog.DebugContext(ctx, "aws verifier: credentials are inactive")
			return finding.VerificationResult{
				Status:  finding.StatusVerifiedInactive,
				Message: "AWS credentials are invalid or inactive",
			}
		}
		// AWS error bodies can echo the caller's Access Key ID (and, for some
		// signature errors, request context) back to the client. Strip the raw
		// credentials before the message reaches a log record or the returned
		// VerificationResult (which flows into JSON/SARIF/CSV output).
		safeMsg := redactSDKError(err, raw)
		slog.ErrorContext(ctx, "aws verifier: verification failed", slog.String("error", safeMsg))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("verification failed: %s", safeMsg),
		}
	}

	extra := make(map[string]string)
	if output.Account != nil {
		extra["account"] = aws.ToString(output.Account)
	}
	if output.Arn != nil {
		extra["arn"] = aws.ToString(output.Arn)
	}
	if output.UserId != nil {
		extra["user_id"] = aws.ToString(output.UserId)
	}

	slog.InfoContext(
		ctx, "aws verifier: credentials are active",
		slog.String("account", extra["account"]),
		slog.String("arn", extra["arn"]),
	)

	return finding.VerificationResult{
		Status:    finding.StatusVerifiedActive,
		Message:   "AWS credentials are active",
		ExtraData: extra,
	}
}

// authErrorCodes is the set of STS/IAM error codes that prove the access key
// itself is invalid, inactive, or expired (i.e. authentication failed).
//
// Note: "AccessDenied" is deliberately NOT in this set. AccessDenied means the
// credentials authenticated successfully but lack permission for the call — the
// key is therefore active, not inactive. Treating it as inactive would be a
// false negative.
var authErrorCodes = map[string]struct{}{
	"InvalidClientTokenId":        {},
	"SignatureDoesNotMatch":       {},
	"ExpiredToken":                {},
	"ExpiredTokenException":       {},
	"InvalidToken":                {},
	"TokenRefreshRequired":        {},
	"AuthFailure":                 {},
	"UnrecognizedClientException": {},
	"IncompleteSignature":         {},
}

// isAuthError reports whether the error indicates invalid/inactive credentials.
//
// It prefers the typed smithy.APIError code (exact match) and falls back to a
// substring scan of the error message for callers (and tests) that surface a
// plain error rather than a typed AWS API error. Both paths use the exact
// authErrorCodes set so that, for example, "AccessDenied" is never classified
// as an authentication failure.
func isAuthError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		_, ok := authErrorCodes[apiErr.ErrorCode()]
		return ok
	}

	errMsg := err.Error()
	for code := range authErrorCodes {
		if strings.Contains(errMsg, code) {
			return true
		}
	}
	return false
}

// redactSDKError returns the SDK error text with the raw Access Key ID and
// Secret Access Key stripped, so no raw credential can reach a log record or an
// output-bound VerificationResult.Message. It reuses the shared httpx redaction
// chokepoint for the primary credential and masks the secret key on top of it.
func redactSDKError(err error, raw detector.RawFinding) string {
	msg := httpx.RedactError(err, string(raw.Raw))
	if len(raw.RawV2) > 0 {
		msg = strings.ReplaceAll(msg, string(raw.RawV2), "[REDACTED]")
	}
	return msg
}

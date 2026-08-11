package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	awsdetector "github.com/HodeTech/leakwatch/internal/detector/aws"
	"github.com/HodeTech/leakwatch/internal/detector/testutil"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_RealDetectorOutput_ReachesSTSContract(t *testing.T) {
	fixture := testutil.RegisteredDetectorFixtures()[detectorID]
	findings := testutil.ScanViaMatcher(&awsdetector.AccessKeyID{}, fixture.Input)
	require.Len(t, findings, 1)
	require.NotEmpty(t, findings[0].RawV2)

	v := &Verifier{client: &mockSTSClient{output: &sts.GetCallerIdentityOutput{
		Account: aws.String("123456789012"), Arn: aws.String("arn:aws:iam::123456789012:user/fixture"),
		UserId: aws.String("AIDAFIXTURE"),
	}}}
	result := v.Verify(t.Context(), findings[0])
	require.Equal(t, finding.StatusVerifiedActive, result.Status)
}

// mockSTSClient implements stsClient for testing.
type mockSTSClient struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (m *mockSTSClient) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.output, m.err
}

func TestVerify_NoSecretKey_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("AKIAIOSFODNN7EXAMPLE"),
		RawV2:      nil,
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "secret access key not found", result.Message)
}

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "aws-access-key-id", v.Type())
}

func TestVerify_ValidCredentials_ReturnsActive(t *testing.T) {
	mock := &mockSTSClient{
		output: &sts.GetCallerIdentityOutput{
			Account: aws.String("123456789012"),
			Arn:     aws.String("arn:aws:iam::123456789012:user/testuser"),
			UserId:  aws.String("AIDAEXAMPLE"),
		},
	}
	v := &Verifier{client: mock}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("AKIAIOSFODNN7EXAMPLE"),
		RawV2:      []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "AWS credentials are active", result.Message)
	assert.Equal(t, "123456789012", result.ExtraData["account"])
	assert.Equal(t, "arn:aws:iam::123456789012:user/testuser", result.ExtraData["arn"])
	assert.Equal(t, "AIDAEXAMPLE", result.ExtraData["user_id"])
}

func TestVerify_InvalidCredentials_ReturnsInactive(t *testing.T) {
	mock := &mockSTSClient{
		err: errors.New("operation error STS: GetCallerIdentity, InvalidClientTokenId: The security token included in the request is invalid"),
	}
	v := &Verifier{client: mock}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("AKIAIOSFODNN7EXAMPLE"),
		RawV2:      []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
}

func TestVerify_TypedAuthError_ReturnsInactive(t *testing.T) {
	mock := &mockSTSClient{
		err: &smithy.OperationError{
			ServiceID:     "STS",
			OperationName: "GetCallerIdentity",
			Err: &smithy.GenericAPIError{
				Code:    "InvalidClientTokenId",
				Message: "The security token included in the request is invalid",
			},
		},
	}
	v := &Verifier{client: mock}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("AKIAIOSFODNN7EXAMPLE"),
		RawV2:      []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
}

// TestVerify_AccessDenied_ReturnsVerifyError ensures AccessDenied is NOT
// classified as an authentication failure: the credentials authenticated but
// lacked permission, so they are active, not inactive. Because the verifier
// cannot read the caller identity it returns a verify error rather than
// falsely claiming the key is inactive.
func TestVerify_AccessDenied_ReturnsVerifyError(t *testing.T) {
	mock := &mockSTSClient{
		err: &smithy.OperationError{
			ServiceID:     "STS",
			OperationName: "GetCallerIdentity",
			Err: &smithy.GenericAPIError{
				Code:    "AccessDenied",
				Message: "User is not authorized to perform sts:GetCallerIdentity",
			},
		},
	}
	v := &Verifier{client: mock}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("AKIAIOSFODNN7EXAMPLE"),
		RawV2:      []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	assert.NotEqual(t, finding.StatusVerifiedInactive, result.Status)
	assert.Equal(t, finding.StatusVerifyError, result.Status)
}

func TestIsAuthError_ExactCodeMatching(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"invalid token code", &smithy.GenericAPIError{Code: "InvalidClientTokenId"}, true},
		{"expired token code", &smithy.GenericAPIError{Code: "ExpiredToken"}, true},
		{"signature mismatch", &smithy.GenericAPIError{Code: "SignatureDoesNotMatch"}, true},
		{"access denied is not auth error", &smithy.GenericAPIError{Code: "AccessDenied"}, false},
		{"throttling is not auth error", &smithy.GenericAPIError{Code: "Throttling"}, false},
		{"plain invalid token message", errors.New("operation error STS: InvalidClientTokenId: bad"), true},
		{"plain network error", fmt.Errorf("dial tcp: %w", errors.New("timeout")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAuthError(tt.err))
		})
	}
}

// TestVerify_ErrorEchoingCredentials_Redacts ensures that when the SDK error
// text echoes the raw Access Key ID or Secret Access Key back (as AWS signature
// errors can), neither raw credential appears in the log/output-bound message.
func TestVerify_ErrorEchoingCredentials_Redacts(t *testing.T) {
	const (
		accessKeyID = "AKIAIOSFODNN7EXAMPLE"
		secretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	)
	mock := &mockSTSClient{
		err: fmt.Errorf(
			"InternalFailure: the AccessKeyId %s with secret %s could not be processed",
			accessKeyID, secretKey,
		),
	}
	v := &Verifier{client: mock}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(accessKeyID),
		RawV2:      []byte(secretKey),
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusVerifyError, result.Status)
	assert.NotContains(t, result.Message, accessKeyID)
	assert.NotContains(t, result.Message, secretKey)
	assert.Contains(t, result.Message, "[REDACTED]")
}

func TestVerify_OtherError_ReturnsVerifyError(t *testing.T) {
	mock := &mockSTSClient{
		err: errors.New("network timeout"),
	}
	v := &Verifier{client: mock}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("AKIAIOSFODNN7EXAMPLE"),
		RawV2:      []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		Redacted:   "AKIA****MPLE",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "network timeout")
}

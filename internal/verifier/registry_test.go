package verifier

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
)

// mockVerifier is a test double implementing the Verifier interface.
type mockVerifier struct {
	id     string
	result finding.VerificationResult
}

func (m *mockVerifier) Type() string { return m.id }

func (m *mockVerifier) Verify(_ context.Context, _ detector.RawFinding) finding.VerificationResult {
	return m.result
}

func newMock(id string) *mockVerifier {
	return &mockVerifier{
		id: id,
		result: finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "mock verified",
		},
	}
}

func TestRegister_SingleVerifier_Succeeds(t *testing.T) {
	t.Cleanup(func() { Reset() })

	Register(newMock("aws-access-key-id"))

	got, ok := Get("aws-access-key-id")
	assert.True(t, ok)
	assert.Equal(t, "aws-access-key-id", got.Type())
}

func TestRegister_DuplicateType_Panics(t *testing.T) {
	t.Cleanup(func() { Reset() })

	Register(newMock("github-token"))

	assert.Panics(t, func() {
		Register(newMock("github-token"))
	})
}

func TestRegister_NilOrEmptyType_PanicsWithoutMutatingRegistry(t *testing.T) {
	Reset()
	var typedNil *mockVerifier
	assert.Panics(t, func() { Register(nil) })
	assert.Panics(t, func() { Register(typedNil) })
	assert.Panics(t, func() { Register(newMock("")) })
	assert.Empty(t, All())
}

func TestGet_UnregisteredType_ReturnsFalse(t *testing.T) {
	t.Cleanup(func() { Reset() })

	_, ok := Get("nonexistent")
	assert.False(t, ok)
}

func TestAll_MultipleVerifiers_ReturnsSorted(t *testing.T) {
	t.Cleanup(func() { Reset() })

	Register(newMock("slack-token"))
	Register(newMock("aws-access-key-id"))
	Register(newMock("github-token"))

	all := All()
	assert.Len(t, all, 3)
	assert.Equal(t, "aws-access-key-id", all[0].Type())
	assert.Equal(t, "github-token", all[1].Type())
	assert.Equal(t, "slack-token", all[2].Type())
}

func TestAll_EmptyRegistry_ReturnsEmpty(t *testing.T) {
	t.Cleanup(func() { Reset() })

	all := All()
	assert.Empty(t, all)
}

func TestReset_ClearsRegistry(t *testing.T) {
	Register(newMock("test-verifier"))
	assert.Len(t, All(), 1)

	Reset()
	assert.Empty(t, All())
}

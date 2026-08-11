package detector

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDetector struct {
	id string
}

func (m *mockDetector) ID() string { return m.id }

func (m *mockDetector) Description() string { return "mock" }

func (m *mockDetector) Keywords() []string { return nil }

func (m *mockDetector) Scan(_ context.Context, _ []byte) []RawFinding { return nil }

func (m *mockDetector) Severity() finding.Severity { return finding.SeverityLow }

func TestRegister_AndAll_ReturnsAllDetectors(t *testing.T) {
	Reset()

	Register(&mockDetector{id: "test-1"})
	Register(&mockDetector{id: "test-2"})

	all := All()
	assert.Len(t, all, 2)
}

func TestRegister_DuplicateID_Panics(t *testing.T) {
	Reset()

	Register(&mockDetector{id: "dup"})

	assert.Panics(t, func() {
		Register(&mockDetector{id: "dup"})
	})
}

func TestRegister_NilOrEmptyID_PanicsWithoutMutatingRegistry(t *testing.T) {
	Reset()
	var typedNil *mockDetector
	assert.Panics(t, func() { Register(nil) })
	assert.Panics(t, func() { Register(typedNil) })
	assert.Panics(t, func() { Register(&mockDetector{}) })
	assert.Empty(t, All())
}

func TestAll_EmptyRegistry_ReturnsEmpty(t *testing.T) {
	Reset()

	all := All()
	assert.Empty(t, all)
}

func TestAll_MultipleDetectors_ReturnsSortedByID(t *testing.T) {
	Reset()

	// Intentionally register in non-alphabetical order
	Register(&mockDetector{id: "zebra-detector"})
	Register(&mockDetector{id: "alpha-detector"})
	Register(&mockDetector{id: "middle-detector"})

	all := All()
	require.Len(t, all, 3)

	assert.Equal(t, "alpha-detector", all[0].ID())
	assert.Equal(t, "middle-detector", all[1].ID())
	assert.Equal(t, "zebra-detector", all[2].ID())
}

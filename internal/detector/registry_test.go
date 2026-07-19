package detector

import (
	"context"
	"sync"
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

func TestGet_ExistingDetector_ReturnsDetector(t *testing.T) {
	Reset()

	Register(&mockDetector{id: "test-1"})

	d, ok := Get("test-1")
	require.True(t, ok)
	assert.Equal(t, "test-1", d.ID())
}

func TestGet_NonExistingDetector_ReturnsFalse(t *testing.T) {
	Reset()

	_, ok := Get("not-found")
	assert.False(t, ok)
}

func TestRegister_DuplicateID_Panics(t *testing.T) {
	Reset()

	Register(&mockDetector{id: "dup"})

	assert.Panics(t, func() {
		Register(&mockDetector{id: "dup"})
	})
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

func TestRegisterIfAbsent_NewID_RegistersAndReturnsTrue(t *testing.T) {
	Reset()

	ok := RegisterIfAbsent(&mockDetector{id: "new-detector"})
	assert.True(t, ok)

	d, found := Get("new-detector")
	require.True(t, found)
	assert.Equal(t, "new-detector", d.ID())
}

func TestRegisterIfAbsent_DuplicateID_ReturnsFalseWithoutPanicOrOverwrite(t *testing.T) {
	Reset()

	original := &mockDetector{id: "dup-detector"}
	Register(original)

	assert.NotPanics(t, func() {
		ok := RegisterIfAbsent(&mockDetector{id: "dup-detector"})
		assert.False(t, ok)
	})

	// The original registration must be untouched by the rejected attempt.
	d, found := Get("dup-detector")
	require.True(t, found)
	assert.Same(t, original, d)

	all := All()
	assert.Len(t, all, 1)
}

// TestRegisterIfAbsent_ConcurrentDuplicateIDs_ExactlyOneWinsAtomically drives
// many goroutines racing to register the same ID via RegisterIfAbsent, and
// asserts the registry ends up with exactly one entry with no data race
// (run with -race). This locks down the "atomically" guarantee documented on
// RegisterIfAbsent for runtime-supplied detectors such as custom rules,
// which may be registered concurrently with other scan setup.
func TestRegisterIfAbsent_ConcurrentDuplicateIDs_ExactlyOneWinsAtomically(t *testing.T) {
	Reset()

	const goroutines = 50
	var wg sync.WaitGroup
	var successCount int32
	var mu sync.Mutex

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			if RegisterIfAbsent(&mockDetector{id: "concurrent-dup"}) {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), successCount, "exactly one registration must win")

	all := All()
	assert.Len(t, all, 1)
	assert.Equal(t, "concurrent-dup", all[0].ID())
}

// TestRegisterIfAbsent_ConcurrentDistinctIDs_AllSucceed exercises concurrent
// registration of distinct IDs to ensure no entries are lost or corrupted
// under concurrent access (run with -race).
func TestRegisterIfAbsent_ConcurrentDistinctIDs_AllSucceed(t *testing.T) {
	Reset()

	const goroutines = 50
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			id := "detector-" + string(rune('a'+n%26)) + string(rune('0'+n/26))
			ok := RegisterIfAbsent(&mockDetector{id: id})
			assert.True(t, ok)
		}(i)
	}
	wg.Wait()

	all := All()
	assert.Len(t, all, goroutines)
}

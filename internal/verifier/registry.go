package verifier

import (
	"sort"
	"sync"
)

var (
	mu        sync.RWMutex
	verifiers = make(map[string]Verifier)
)

// Register adds a verifier to the global registry.
// Each verifier package calls this function in its init() function.
// Panics if a verifier with the same Type() is already registered.
func Register(v Verifier) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := verifiers[v.Type()]; exists {
		panic("duplicate verifier type: " + v.Type())
	}
	verifiers[v.Type()] = v
}

// Get returns the verifier registered for the given detector ID.
//
// It is the public single-lookup counterpart to All (which the engine uses to
// snapshot every verifier). Get is retained for callers that need to resolve a
// single verifier by detector ID directly against the global registry (for
// example an ad-hoc single-secret verification path) without constructing an
// Engine.
func Get(detectorID string) (Verifier, bool) {
	mu.RLock()
	defer mu.RUnlock()
	v, ok := verifiers[detectorID]
	return v, ok
}

// All returns all registered verifiers sorted by Type().
func All() []Verifier {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Verifier, 0, len(verifiers))
	for _, v := range verifiers {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Type() < result[j].Type()
	})
	return result
}

// Reset clears all registered verifiers.
// WARNING: This is for testing only and is NOT safe for concurrent use.
// It must be called from a single goroutine (typically TestMain or a test setup).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	verifiers = make(map[string]Verifier)
}

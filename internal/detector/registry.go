package detector

import (
	"reflect"
	"sort"
	"sync"
)

var (
	mu        sync.RWMutex
	detectors = make(map[string]Detector)
)

// Register adds a detector to the central registry.
// Each detector package calls this in its init() function.
// Panics if a duplicate ID is registered.
func Register(d Detector) {
	if d == nil || isNilDetector(d) {
		panic("cannot register a nil detector")
	}
	id := d.ID()
	if id == "" {
		panic("cannot register a detector with an empty ID")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, exists := detectors[id]; exists {
		panic("duplicate detector ID: " + id)
	}
	detectors[id] = d
}

func isNilDetector(d Detector) bool {
	value := reflect.ValueOf(d)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// All returns all registered detectors sorted by ID.
func All() []Detector {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Detector, 0, len(detectors))
	for _, d := range detectors {
		result = append(result, d)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID() < result[j].ID()
	})
	return result
}

// Reset clears all registered detectors. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	detectors = make(map[string]Detector)
}

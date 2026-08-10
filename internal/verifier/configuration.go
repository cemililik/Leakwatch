package verifier

import (
	"fmt"
	"reflect"
)

// TrustedInstanceConfigurer is implemented by verifiers whose live endpoint
// must be selected from explicit operator context rather than scanned content.
// Implementations must validate the supplied origin and return an independent
// verifier value; they must not mutate the process-global registry instance.
type TrustedInstanceConfigurer interface {
	WithTrustedInstance(instanceURL string) (Verifier, error)
}

// ConfigureTrustedInstance returns a per-run verifier slice in which detectorID
// is configured for an explicit operator-supplied instance. The input slice and
// the process-global registry objects are never mutated.
func ConfigureTrustedInstance(vs []Verifier, detectorID, instanceURL string) ([]Verifier, error) {
	configured := append([]Verifier(nil), vs...)
	if detectorID == "" {
		return nil, fmt.Errorf("trusted instance verifier ID must not be empty")
	}

	target := -1
	seen := make(map[string]struct{}, len(configured))
	for i, candidate := range configured {
		if isNilVerifier(candidate) {
			return nil, fmt.Errorf("verifier list contains nil entry at index %d", i)
		}
		id := candidate.Type()
		if id == "" {
			return nil, fmt.Errorf("verifier list contains empty type at index %d", i)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("verifier list contains duplicate type %q", id)
		}
		seen[id] = struct{}{}
		if id == detectorID {
			target = i
		}
	}
	if target < 0 {
		return nil, fmt.Errorf("verifier %q is not registered", detectorID)
	}

	configurer, ok := configured[target].(TrustedInstanceConfigurer)
	if !ok {
		return nil, fmt.Errorf("verifier %q does not accept trusted instance configuration", detectorID)
	}
	replacement, err := configurer.WithTrustedInstance(instanceURL)
	if err != nil {
		return nil, err
	}
	if isNilVerifier(replacement) || replacement.Type() != detectorID {
		return nil, fmt.Errorf("verifier %q returned an invalid configured replacement", detectorID)
	}
	configured[target] = replacement
	return configured, nil
}

func isNilVerifier(v Verifier) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

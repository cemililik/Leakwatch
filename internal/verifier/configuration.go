package verifier

import "fmt"

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
	for i, candidate := range configured {
		if candidate.Type() != detectorID {
			continue
		}
		configurer, ok := candidate.(TrustedInstanceConfigurer)
		if !ok {
			return nil, fmt.Errorf("verifier %q does not accept trusted instance configuration", detectorID)
		}
		replacement, err := configurer.WithTrustedInstance(instanceURL)
		if err != nil {
			return nil, err
		}
		if replacement == nil || replacement.Type() != detectorID {
			return nil, fmt.Errorf("verifier %q returned an invalid configured replacement", detectorID)
		}
		configured[i] = replacement
		return configured, nil
	}
	return nil, fmt.Errorf("verifier %q is not registered", detectorID)
}

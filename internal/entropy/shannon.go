// Package entropy provides Shannon entropy calculation functions.
package entropy

import "math"

// Calculate computes the Shannon entropy (base 2, in bits per byte) of data.
// It returns 0.0 for a degenerate distribution (e.g. all identical bytes,
// including the empty input) up to ~8.0 for a perfectly uniform distribution
// over all 256 byte values.
func Calculate(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(len(data))
	entropy := 0.0
	for _, count := range &freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

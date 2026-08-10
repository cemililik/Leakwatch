// Package verifier provides the secret verification infrastructure.
// Verifiers check whether detected secrets are active or inactive
// by making controlled, read-only API calls to the relevant services.
package verifier

import (
	"context"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Verifier validates whether a detected secret is active or inactive.
// Each implementation targets a specific detector type (e.g., AWS, GitHub).
// Implementations MUST NOT log or persist the raw secret content.
type Verifier interface {
	// Type returns the detector ID this verifier handles.
	// It must match the corresponding Detector.ID() value.
	Type() string

	// Verify checks if the detected secret is valid/active.
	// It may make network calls, so the context must be respected for cancellation.
	Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult
}

// RequestGate is an engine-owned admission gate for a single outbound
// verification request. A RequestGatedVerifier must call it immediately before
// every provider request and must return a non-nil result without sending the
// request when admission fails.
type RequestGate func() *finding.VerificationResult

// RequestGatedVerifier is implemented by verifiers that may issue more than
// one provider request for a finding (for example a bounded regional fallback).
// The engine uses the declared maximum to fail closed on runaway attempts while
// pacing each request at its actual send point.
type RequestGatedVerifier interface {
	Verifier

	// VerificationRequestBudget is the maximum number of provider requests that
	// VerifyWithRequestGate may attempt for one finding.
	VerificationRequestBudget() int

	// VerifyWithRequestGate performs verification and calls gate immediately
	// before every outbound provider request.
	VerifyWithRequestGate(
		ctx context.Context,
		raw detector.RawFinding,
		gate RequestGate,
	) finding.VerificationResult
}

// VerifyPair associates a Finding with its corresponding RawFinding
// so the verification engine can pass raw secret data to verifiers
// while returning enriched Finding objects.
type VerifyPair struct {
	Finding finding.Finding
	Raw     detector.RawFinding
}

package verifier

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

type trustedInstanceMock struct {
	id          string
	instance    string
	err         error
	replacement Verifier
}

func (m *trustedInstanceMock) Type() string { return m.id }

func (m *trustedInstanceMock) Verify(context.Context, detector.RawFinding) finding.VerificationResult {
	return finding.VerificationResult{}
}

func (m *trustedInstanceMock) WithTrustedInstance(instanceURL string) (Verifier, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.replacement != nil {
		return m.replacement, nil
	}
	return &trustedInstanceMock{id: m.id, instance: instanceURL}, nil
}

func TestConfigureTrustedInstance_ReturnsIndependentReplacement(t *testing.T) {
	original := &trustedInstanceMock{id: "contextual"}
	other := newMock("other")
	input := []Verifier{original, other}

	got, err := ConfigureTrustedInstance(input, "contextual", "https://operator.example")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Same(t, original, input[0])
	assert.Same(t, other, input[1])
	assert.NotSame(t, original, got[0])
	assert.Equal(t, "https://operator.example", got[0].(*trustedInstanceMock).instance)
	assert.Same(t, other, got[1])
}

func TestConfigureTrustedInstance_RejectsInvalidContracts(t *testing.T) {
	var typedNil *trustedInstanceMock
	tests := []struct {
		name string
		vs   []Verifier
		id   string
	}{
		{name: "missing", vs: []Verifier{newMock("other")}, id: "missing"},
		{name: "not configurable", vs: []Verifier{newMock("plain")}, id: "plain"},
		{name: "configuration error", vs: []Verifier{&trustedInstanceMock{id: "bad", err: fmt.Errorf("invalid origin")}}, id: "bad"},
		{name: "nil entry", vs: []Verifier{nil}, id: "nil"},
		{name: "typed nil entry", vs: []Verifier{typedNil}, id: "nil"},
		{name: "duplicate type", vs: []Verifier{newMock("duplicate"), newMock("duplicate")}, id: "duplicate"},
		{name: "mismatched replacement", vs: []Verifier{&trustedInstanceMock{id: "contextual", replacement: newMock("other")}}, id: "contextual"},
		{name: "typed nil replacement", vs: []Verifier{&trustedInstanceMock{id: "contextual", replacement: typedNil}}, id: "contextual"},
		{name: "empty target ID", vs: []Verifier{newMock("other")}, id: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ConfigureTrustedInstance(tc.vs, tc.id, "https://operator.example")
			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

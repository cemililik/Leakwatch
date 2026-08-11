package main

import (
	"testing"

	"github.com/HodeTech/leakwatch/internal/meta"
)

func TestValidateStableReleaseTag(t *testing.T) {
	if err := validateStableReleaseTag(meta.ReleaseVersion); err != nil {
		t.Fatalf("validateStableReleaseTag(%q) error = %v", meta.ReleaseVersion, err)
	}
}

func TestValidateStableReleaseTag_FailsClosed(t *testing.T) {
	for _, tag := range []string{
		"",
		"vnext",
		"1.7.0",
		"v01.7.0",
		"v1.7",
		"v1.7.0-rc.1",
		"v999.0.0",
	} {
		t.Run(tag, func(t *testing.T) {
			if err := validateStableReleaseTag(tag); err == nil {
				t.Fatalf("validateStableReleaseTag(%q) error = nil, want fail-closed error", tag)
			}
		})
	}
}

package main

import (
	"testing"

	"github.com/HodeTech/leakwatch/internal/meta"
)

func TestValidateStableReleaseTag(t *testing.T) {
	prerelease, err := validateReleaseTag(meta.ReleaseVersion)
	if err != nil {
		t.Fatalf("validateReleaseTag(%q) error = %v", meta.ReleaseVersion, err)
	}
	if prerelease {
		t.Fatalf("validateReleaseTag(%q) prerelease = true, want false", meta.ReleaseVersion)
	}
}

func TestValidateReleaseTag_AcceptsValidPrereleases(t *testing.T) {
	for _, tag := range []string{"v1.8.0-rc.1", "v2.0.0-beta.2", "v2.0.0-preview-x"} {
		t.Run(tag, func(t *testing.T) {
			prerelease, err := validateReleaseTag(tag)
			if err != nil {
				t.Fatalf("validateReleaseTag(%q) error = %v", tag, err)
			}
			if !prerelease {
				t.Fatalf("validateReleaseTag(%q) prerelease = false, want true", tag)
			}
		})
	}
}

func TestValidateReleaseTag_FailsClosed(t *testing.T) {
	for _, tag := range []string{
		"",
		"vnext",
		"1.7.0",
		"v01.7.0",
		"v1.7",
		"v999.0.0",
		"v1.8.0-",
		"v1.8.0-rc..1",
		"v1.8.0-rc+build",
		"v1.8.0-01",
		"v1.8.0_rc1",
	} {
		t.Run(tag, func(t *testing.T) {
			if _, err := validateReleaseTag(tag); err == nil {
				t.Fatalf("validateReleaseTag(%q) error = nil, want fail-closed error", tag)
			}
		})
	}
}

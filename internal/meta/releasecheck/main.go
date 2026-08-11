// Command releasecheck rejects malformed release tags and prevents a stable
// tag from publishing artifacts whose metadata still names another release.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/HodeTech/leakwatch/internal/meta"
)

var (
	stableTagPattern         = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	prereleaseIdentifierRule = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
)

func main() {
	tag := flag.String("tag", "", "Git release tag being published")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments"))
	}
	prerelease, err := validateReleaseTag(*tag)
	if err != nil {
		fail(err)
	}
	if prerelease {
		fmt.Printf("prerelease tag %s is valid; stable metadata remains %s\n", *tag, meta.ReleaseVersion)
		return
	}
	fmt.Printf("release metadata matches stable tag %s\n", *tag)
}

func validateReleaseTag(tag string) (bool, error) {
	base, prerelease, hasPrerelease := strings.Cut(tag, "-")
	if !stableTagPattern.MatchString(base) {
		return false, fmt.Errorf("release tag %q does not start with a valid vMAJOR.MINOR.PATCH version", tag)
	}
	if !hasPrerelease {
		if tag != meta.ReleaseVersion {
			return false, fmt.Errorf("release tag %q does not match internal/meta.ReleaseVersion %q", tag, meta.ReleaseVersion)
		}
		return false, nil
	}
	if prerelease == "" {
		return false, fmt.Errorf("release tag %q has an empty prerelease suffix", tag)
	}
	for _, identifier := range strings.Split(prerelease, ".") {
		if !prereleaseIdentifierRule.MatchString(identifier) {
			return false, fmt.Errorf("release tag %q has invalid prerelease identifier %q", tag, identifier)
		}
		if len(identifier) > 1 && identifier[0] == '0' && isDecimal(identifier) {
			return false, fmt.Errorf("release tag %q has a numeric prerelease identifier with a leading zero", tag)
		}
	}
	return true, nil
}

func isDecimal(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "releasecheck:", err)
	os.Exit(1)
}

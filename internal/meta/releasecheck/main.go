// Command releasecheck prevents a stable tag from publishing artifacts whose
// canonical product metadata still names a different release.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/meta"
)

var stableTagPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func main() {
	tag := flag.String("tag", "", "stable Git tag being published")
	flag.Parse()
	if flag.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments"))
	}
	if err := validateStableReleaseTag(*tag); err != nil {
		fail(err)
	}
	fmt.Printf("release metadata matches stable tag %s\n", *tag)
}

func validateStableReleaseTag(tag string) error {
	if !stableTagPattern.MatchString(tag) {
		return fmt.Errorf("release tag %q is not a stable vMAJOR.MINOR.PATCH tag", tag)
	}
	if tag != meta.ReleaseVersion {
		return fmt.Errorf("release tag %q does not match internal/meta.ReleaseVersion %q", tag, meta.ReleaseVersion)
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "releasecheck:", err)
	os.Exit(1)
}

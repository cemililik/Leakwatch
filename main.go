package main

import (
	"os"

	"github.com/HodeTech/leakwatch/cmd"
)

// Build information (injected via ldflags).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, date)
	os.Exit(cmd.Execute())
}

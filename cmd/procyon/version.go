package main

import (
	"fmt"
	"runtime/debug"
)

// Set at release time with -ldflags "-X main.version=v0.1.0 -X main.commit=abc123".
var (
	version = ""
	commit  = ""
)

// versionString reports the release version and commit, falling back to what
// the Go toolchain recorded for `go install` and local builds.
func versionString() string {
	v, c := version, commit
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" {
			v = info.Main.Version // "v0.1.0" after go install, "(devel)" locally
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && c == "" {
				c = s.Value
			}
		}
	}
	if v == "" {
		v = "(devel)"
	}
	if c == "" {
		return "procyon " + v
	}
	if len(c) > 12 {
		c = c[:12]
	}
	return fmt.Sprintf("procyon %s (%s)", v, c)
}

// Package version provides build version information.
// Version is set at build time via ldflags:
// go build -ldflags "-X github.com/Rorqualx/flaresolverr-go/pkg/version.Version=1.0.0"
package version

import "runtime"

// Version is the application version, set at build time.
var Version = "dev"

// UserAgent is the default user agent string.
// Fix MEDIUM: Updated Chrome version to 132 (current stable as of early 2025).
// This should be kept up to date to avoid detection by anti-bot systems.
var UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"

// Full returns the full version string.
func Full() string {
	return Version
}

// GoVersion returns the Go runtime version.
func GoVersion() string {
	return runtime.Version()
}

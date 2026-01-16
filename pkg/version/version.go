// Package version provides build version information.
// Version is set at build time via ldflags:
// go build -ldflags "-X github.com/user/flaresolverr-go/pkg/version.Version=1.0.0"
package version

import "runtime"

// Version is the application version, set at build time.
var Version = "dev"

// UserAgent is the default user agent string.
var UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Full returns the full version string.
func Full() string {
	return Version
}

// GoVersion returns the Go runtime version.
func GoVersion() string {
	return runtime.Version()
}

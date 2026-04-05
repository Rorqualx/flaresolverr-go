// Package version provides build version information.
// Version is set at build time via ldflags:
// go build -ldflags "-X github.com/Rorqualx/flaresolverr-go/pkg/version.Version=1.0.0"
package version

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// Version is the application version, set at build time.
var Version = "dev"

// GitHubRepo is the GitHub repository for update checks.
const GitHubRepo = "Rorqualx/flaresolverr-go"

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

// CheckForUpdate queries the GitHub releases API and returns info about a newer
// version if available. Returns empty strings if current version is latest or
// if the check fails (non-blocking).
func CheckForUpdate() (latestVersion, releaseURL string) {
	if Version == "dev" {
		return "", ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", GitHubRepo)
	resp, err := client.Get(url)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ""
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", ""
	}

	// Compare versions (strip "v" prefix)
	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(Version, "v")

	// Simple string comparison — works for semver-like versions
	if latest != current && latest > current {
		return release.TagName, release.HTMLURL
	}

	return "", ""
}

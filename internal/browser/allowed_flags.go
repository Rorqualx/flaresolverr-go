package browser

// AllowedExtraArgs is the whitelist of Chrome flags that can be set per-session.
// Security-sensitive flags are explicitly excluded.
var AllowedExtraArgs = map[string]bool{
	// Safe display/rendering flags
	"--disable-gpu":                 true,
	"--disable-gpu-compositing":     true,
	"--disable-software-rasterizer": true,
	"--force-device-scale-factor":   true,

	// Safe content flags
	"--disable-images":     true,
	"--disable-javascript": true,
	"--disable-extensions": true,
	"--mute-audio":         true,

	// Safe network flags
	"--disable-background-networking": true,
	"--disable-sync":                  true,

	// Safe display flags
	"--hide-scrollbars":  true,
	"--disable-infobars": true,
}

// BlockedExtraArgs contains flags that are explicitly forbidden for security.
var BlockedExtraArgs = map[string]bool{
	"--disable-web-security":           true,
	"--remote-debugging-port":          true,
	"--remote-debugging-address":       true,
	"--allow-running-insecure-content": true,
	"--disable-site-isolation-trials":  true,
	"--no-sandbox":                     true, // already set globally
	"--user-data-dir":                  true,
	"--proxy-server":                   true, // use Proxy field instead
}

// IsAllowedExtraArg checks if a Chrome flag is in the allowed whitelist.
// Flags with values (e.g., --flag=value) are checked by their prefix.
func IsAllowedExtraArg(arg string) bool {
	// Check for exact match
	if AllowedExtraArgs[arg] {
		return true
	}

	// Check for flags with values (--flag=value)
	for allowed := range AllowedExtraArgs {
		if len(arg) > len(allowed) && arg[:len(allowed)] == allowed && arg[len(allowed)] == '=' {
			return true
		}
	}

	return false
}

// IsBlockedExtraArg checks if a Chrome flag is explicitly blocked.
func IsBlockedExtraArg(arg string) bool {
	if BlockedExtraArgs[arg] {
		return true
	}

	// Check for flags with values
	for blocked := range BlockedExtraArgs {
		if len(arg) > len(blocked) && arg[:len(blocked)] == blocked && arg[len(blocked)] == '=' {
			return true
		}
	}

	return false
}

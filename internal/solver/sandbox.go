package solver

// sandboxArgs returns the Chromium sandbox flags for the reconnect bypass,
// which launches Chrome itself rather than through the pool. It mirrors the
// pool's launcher: --no-sandbox unless BROWSER_SANDBOX=true.
func sandboxArgs(sandboxEnabled bool) []string {
	if sandboxEnabled {
		return nil
	}
	return []string{"--no-sandbox"}
}

package browser

import (
	"testing"

	"github.com/go-rod/rod/lib/launcher/flags"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// TestCreateLauncherSandboxFlag verifies --no-sandbox follows BROWSER_SANDBOX:
// present by default, absent when the sandbox is requested. go-rod adds the
// flag on its own inside a container, so "absent" must hold there too.
func TestCreateLauncherSandboxFlag(t *testing.T) {
	tests := []struct {
		name          string
		sandbox       bool
		wantNoSandbox bool
	}{
		{name: "default keeps the sandbox off", sandbox: false, wantNoSandbox: true},
		{name: "BROWSER_SANDBOX=true keeps the sandbox on", sandbox: true, wantNoSandbox: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &Pool{config: &config.Config{Headless: true, BrowserSandbox: tt.sandbox}}

			l := pool.createLauncher("")
			if got := l.Has(flags.NoSandbox); got != tt.wantNoSandbox {
				t.Errorf("launcher has --no-sandbox = %v, want %v", got, tt.wantNoSandbox)
			}
			// Chromium refuses to start with the sandbox on and the zygote off
			if got := l.Has("no-zygote"); got != tt.wantNoSandbox {
				t.Errorf("launcher has --no-zygote = %v, want %v", got, tt.wantNoSandbox)
			}
			if got := pool.SandboxEnabled(); got != tt.sandbox {
				t.Errorf("SandboxEnabled() = %v, want %v", got, tt.sandbox)
			}
		})
	}
}

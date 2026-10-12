package config

import (
	"testing"
)

// TestCaptchaMaxExternalSolves covers the per-request budget of paid solves:
// one by default, never more than the hard cap, and zero buys nothing.
func TestCaptchaMaxExternalSolves(t *testing.T) {
	tests := []struct {
		name string
		env  string // empty means unset
		want int
	}{
		{name: "default", want: 1},
		{name: "explicit one", env: "1", want: 1},
		{name: "two", env: "2", want: 2},
		{name: "at the cap", env: "3", want: 3},
		{name: "above the cap is clamped", env: "50", want: 3},
		{name: "zero disables buying", env: "0", want: 0},
		{name: "negative is treated as zero", env: "-4", want: 0},
		{name: "garbage falls back to the default", env: "many", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("CAPTCHA_MAX_EXTERNAL_SOLVES", tt.env)
			}
			cfg := Load()
			cfg.Validate()
			if cfg.CaptchaMaxExternalSolves != tt.want {
				t.Errorf("CaptchaMaxExternalSolves = %d, want %d", cfg.CaptchaMaxExternalSolves, tt.want)
			}
		})
	}
}

// TestCaptchaFallbackIsOffByDefault pins the "nothing is bought unless asked"
// default: keys alone do not enable the fallback.
func TestCaptchaFallbackIsOffByDefault(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		enabled bool
	}{
		{name: "nothing set"},
		{name: "keys without the switch", env: map[string]string{
			"TWOCAPTCHA_API_KEY": "configured-value-1", "CAPSOLVER_API_KEY": "configured-value-2",
		}},
		{name: "switch without keys", env: map[string]string{"CAPTCHA_FALLBACK_ENABLED": "true"}},
		{name: "switch off with keys", env: map[string]string{
			"CAPTCHA_FALLBACK_ENABLED": "false", "TWOCAPTCHA_API_KEY": "configured-value-1",
		}},
		{name: "switch and a key", enabled: true, env: map[string]string{
			"CAPTCHA_FALLBACK_ENABLED": "true", "ANTICAPTCHA_API_KEY": "configured-value-3",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			cfg := Load()
			cfg.Validate()
			if got := cfg.HasCaptchaFallback(); got != tt.enabled {
				t.Errorf("HasCaptchaFallback() = %v, want %v", got, tt.enabled)
			}
		})
	}
}

func TestValidateProviderBaseURL(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "http://fake-provider:8080", want: "http://fake-provider:8080"},
		{raw: "https://gateway.example.com/captcha/", want: "https://gateway.example.com/captcha"},
		{raw: "  https://gateway.example.com  ", want: "https://gateway.example.com"},
		{raw: "http://127.0.0.1:9000/index.cgi", want: "http://127.0.0.1:9000/index.cgi"},
		{raw: "gateway.example.com", wantErr: true},
		{raw: "ftp://gateway.example.com", wantErr: true},
		{raw: "file:///etc/passwd", wantErr: true},
		{raw: "https://", wantErr: true},
		{raw: "https://user:secret@gateway.example.com", wantErr: true},
		{raw: "https://gateway.example.com/?key=1", wantErr: true},
		{raw: "https://gateway.example.com/#frag", wantErr: true},
		{raw: "http://bad host/", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := validateProviderBaseURL(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateProviderBaseURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("validateProviderBaseURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestCaptchaBaseURLOverrides: valid overrides are loaded for every provider; a
// malformed one is dropped AND switches the server-side fallback off, so a typo
// can never send the server's keys to the provider's real, paid API.
func TestCaptchaBaseURLOverrides(t *testing.T) {
	t.Run("valid overrides", func(t *testing.T) {
		t.Setenv("CAPTCHA_FALLBACK_ENABLED", "true")
		t.Setenv("TWOCAPTCHA_API_KEY", "configured-value-1")
		t.Setenv("TWOCAPTCHA_BASE_URL", "http://fake:8080/")
		t.Setenv("CAPSOLVER_BASE_URL", "http://fake:8081")
		t.Setenv("ANTICAPTCHA_BASE_URL", "https://gw.example.com/anti")
		t.Setenv("NINEKW_BASE_URL", "http://fake:8083/index.cgi")

		cfg := Load()
		cfg.Validate()

		got := []string{cfg.Captcha2CaptchaBaseURL, cfg.CaptchaCapSolverBaseURL, cfg.CaptchaAntiCaptchaBaseURL, cfg.Captcha9kwBaseURL}
		want := []string{"http://fake:8080", "http://fake:8081", "https://gw.example.com/anti", "http://fake:8083/index.cgi"}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("base URL %d = %q, want %q", i, got[i], want[i])
			}
		}
		if !cfg.HasCaptchaFallback() {
			t.Error("valid overrides must not disable the fallback")
		}
	})

	t.Run("no overrides by default", func(t *testing.T) {
		cfg := Load()
		cfg.Validate()
		if cfg.Captcha2CaptchaBaseURL != "" || cfg.CaptchaCapSolverBaseURL != "" ||
			cfg.CaptchaAntiCaptchaBaseURL != "" || cfg.Captcha9kwBaseURL != "" {
			t.Error("base URL overrides must be empty by default")
		}
	})

	for _, env := range []string{"TWOCAPTCHA_BASE_URL", "CAPSOLVER_BASE_URL", "ANTICAPTCHA_BASE_URL", "NINEKW_BASE_URL"} {
		t.Run("malformed "+env+" disables the fallback", func(t *testing.T) {
			t.Setenv("CAPTCHA_FALLBACK_ENABLED", "true")
			t.Setenv("TWOCAPTCHA_API_KEY", "configured-value-1")
			t.Setenv(env, "fake-provider:8080")

			cfg := Load()
			cfg.Validate()

			if cfg.HasCaptchaFallback() {
				t.Error("HasCaptchaFallback() = true with a malformed base URL override")
			}
			if cfg.Captcha2CaptchaBaseURL != "" || cfg.CaptchaCapSolverBaseURL != "" ||
				cfg.CaptchaAntiCaptchaBaseURL != "" || cfg.Captcha9kwBaseURL != "" {
				t.Error("the malformed override was kept")
			}
		})
	}
}

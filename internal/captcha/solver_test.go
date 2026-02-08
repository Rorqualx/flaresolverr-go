package captcha

import (
	"testing"
	"time"
)

func TestSolverChain_ShouldFallback(t *testing.T) {
	tests := []struct {
		name           string
		nativeAttempts int
		attempts       int
		enabled        bool
		want           bool
	}{
		{
			name:           "should fallback after reaching threshold",
			nativeAttempts: 3,
			attempts:       3,
			enabled:        true,
			want:           true,
		},
		{
			name:           "should not fallback before threshold",
			nativeAttempts: 3,
			attempts:       2,
			enabled:        true,
			want:           false,
		},
		{
			name:           "should not fallback when disabled",
			nativeAttempts: 3,
			attempts:       5,
			enabled:        false,
			want:           false,
		},
		{
			name:           "should fallback after exceeding threshold",
			nativeAttempts: 3,
			attempts:       10,
			enabled:        true,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewSolverChain(SolverChainConfig{
				NativeAttempts:  tt.nativeAttempts,
				FallbackEnabled: tt.enabled,
			})

			got := chain.ShouldFallback(tt.attempts)
			if got != tt.want {
				t.Errorf("ShouldFallback(%d) = %v, want %v", tt.attempts, got, tt.want)
			}
		})
	}
}

func TestSolverChain_NativeAttemptsValidation(t *testing.T) {
	tests := []struct {
		name           string
		nativeAttempts int
		want           int
	}{
		{
			name:           "zero is set to default",
			nativeAttempts: 0,
			want:           3,
		},
		{
			name:           "negative is set to default",
			nativeAttempts: -5,
			want:           3,
		},
		{
			name:           "valid value is kept",
			nativeAttempts: 5,
			want:           5,
		},
		{
			name:           "too high is capped",
			nativeAttempts: 100,
			want:           10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewSolverChain(SolverChainConfig{
				NativeAttempts: tt.nativeAttempts,
			})

			got := chain.NativeAttempts()
			if got != tt.want {
				t.Errorf("NativeAttempts() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSolverChain_IsEnabled(t *testing.T) {
	t.Run("enabled when configured", func(t *testing.T) {
		chain := NewSolverChain(SolverChainConfig{
			FallbackEnabled: true,
		})
		if !chain.IsEnabled() {
			t.Error("IsEnabled() = false, want true")
		}
	})

	t.Run("disabled by default", func(t *testing.T) {
		chain := NewSolverChain(SolverChainConfig{})
		if chain.IsEnabled() {
			t.Error("IsEnabled() = true, want false")
		}
	})
}

func TestSolverChain_HasProviders(t *testing.T) {
	t.Run("no providers", func(t *testing.T) {
		chain := NewSolverChain(SolverChainConfig{})
		if chain.HasProviders() {
			t.Error("HasProviders() = true, want false")
		}
	})

	t.Run("with unconfigured provider", func(t *testing.T) {
		chain := NewSolverChain(SolverChainConfig{
			Providers: []CaptchaSolver{
				NewTwoCaptchaSolver(TwoCaptchaConfig{}), // No API key
			},
		})
		if chain.HasProviders() {
			t.Error("HasProviders() = true with unconfigured provider, want false")
		}
	})

	t.Run("with configured provider", func(t *testing.T) {
		chain := NewSolverChain(SolverChainConfig{
			Providers: []CaptchaSolver{
				NewTwoCaptchaSolver(TwoCaptchaConfig{APIKey: "test-key"}),
			},
		})
		if !chain.HasProviders() {
			t.Error("HasProviders() = false with configured provider, want true")
		}
	})
}

func TestTurnstileRequest_Fields(t *testing.T) {
	req := &TurnstileRequest{
		SiteKey:   "0x4AAAAAAA",
		PageURL:   "https://example.com",
		UserAgent: "Mozilla/5.0",
		Action:    "login",
		CData:     "test-data",
	}

	if req.SiteKey != "0x4AAAAAAA" {
		t.Errorf("SiteKey = %q, want %q", req.SiteKey, "0x4AAAAAAA")
	}
	if req.PageURL != "https://example.com" {
		t.Errorf("PageURL = %q, want %q", req.PageURL, "https://example.com")
	}
	if req.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q, want %q", req.UserAgent, "Mozilla/5.0")
	}
}

func TestTurnstileResult_Fields(t *testing.T) {
	result := &TurnstileResult{
		Token:     "test-token",
		SolveTime: 10 * time.Second,
		Cost:      0.002,
		Provider:  "2captcha",
	}

	if result.Token != "test-token" {
		t.Errorf("Token = %q, want %q", result.Token, "test-token")
	}
	if result.SolveTime != 10*time.Second {
		t.Errorf("SolveTime = %v, want %v", result.SolveTime, 10*time.Second)
	}
	if result.Cost != 0.002 {
		t.Errorf("Cost = %f, want %f", result.Cost, 0.002)
	}
	if result.Provider != "2captcha" {
		t.Errorf("Provider = %q, want %q", result.Provider, "2captcha")
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 10, 0},
		{-1, 1, -1},
	}

	for _, tt := range tests {
		got := min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

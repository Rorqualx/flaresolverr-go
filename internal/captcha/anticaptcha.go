// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"time"
)

const (
	// anti-captcha.com API endpoints (compatible with 2Captcha API format)
	antiCaptchaBaseURL = "https://api.anti-captcha.com"
)

// AntiCaptchaSolver implements CaptchaSolver for anti-captcha.com API.
// anti-captcha.com uses the same API format as 2Captcha, so we reuse
// TwoCaptchaSolver with a different base URL.
type AntiCaptchaSolver struct {
	*TwoCaptchaSolver
}

func init() {
	Register("anticaptcha", func(opts ProviderOptions) CaptchaSolver {
		return NewAntiCaptchaSolver(AntiCaptchaConfig(opts))
	})
}

// AntiCaptchaConfig contains configuration for anti-captcha.com solver.
type AntiCaptchaConfig struct {
	APIKey       string
	Timeout      time.Duration
	BaseURL      string        // Override for testing and self-hosted gateways
	PollInterval time.Duration // Override for testing
}

// NewAntiCaptchaSolver creates a new anti-captcha.com solver instance.
func NewAntiCaptchaSolver(cfg AntiCaptchaConfig) *AntiCaptchaSolver {
	if cfg.BaseURL == "" {
		cfg.BaseURL = antiCaptchaBaseURL
	}
	return &AntiCaptchaSolver{
		TwoCaptchaSolver: NewTwoCaptchaSolver(TwoCaptchaConfig(cfg)),
	}
}

// Name returns the provider name.
func (s *AntiCaptchaSolver) Name() string {
	return "anticaptcha"
}

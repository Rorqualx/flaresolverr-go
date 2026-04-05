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

// AntiCaptchaConfig contains configuration for anti-captcha.com solver.
type AntiCaptchaConfig struct {
	APIKey  string
	Timeout time.Duration
}

// NewAntiCaptchaSolver creates a new anti-captcha.com solver instance.
func NewAntiCaptchaSolver(cfg AntiCaptchaConfig) *AntiCaptchaSolver {
	return &AntiCaptchaSolver{
		TwoCaptchaSolver: NewTwoCaptchaSolver(TwoCaptchaConfig{
			APIKey:  cfg.APIKey,
			Timeout: cfg.Timeout,
			BaseURL: antiCaptchaBaseURL,
		}),
	}
}

// Name returns the provider name.
func (s *AntiCaptchaSolver) Name() string {
	return "anticaptcha"
}

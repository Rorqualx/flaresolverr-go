// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"time"
)

const (
	// anti-captcha.com API endpoint (same protocol as 2Captcha)
	antiCaptchaBaseURL = "https://api.anti-captcha.com"

	antiCaptchaName = "anticaptcha"
)

// AntiCaptchaSolver implements CaptchaSolver for anti-captcha.com API.
// anti-captcha.com speaks the same createTask/getTaskResult protocol as
// 2Captcha, so it reuses TwoCaptchaSolver with its own name, base URL and
// field names for the Cloudflare challenge-page parameters.
type AntiCaptchaSolver struct {
	*TwoCaptchaSolver
}

func init() {
	Register(antiCaptchaName, func(opts ProviderOptions) CaptchaSolver {
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
//
// The provider name lives on the embedded solver. It used to be supplied by a
// Name method on this wrapper, which the embedded solver's own methods never
// saw, so every anti-captcha error and result said "2captcha".
func NewAntiCaptchaSolver(cfg AntiCaptchaConfig) *AntiCaptchaSolver {
	return &AntiCaptchaSolver{
		TwoCaptchaSolver: newCreateTaskSolver(antiCaptchaName, dialectAntiCaptcha, antiCaptchaBaseURL, TwoCaptchaConfig(cfg)),
	}
}

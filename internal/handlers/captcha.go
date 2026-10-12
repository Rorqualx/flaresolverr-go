package handlers

import (
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/captcha"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// captchaProviderSettings maps each registered provider name to the server's
// API key and base URL override for it.
func captchaProviderSettings(cfg *config.Config) (keys, baseURLs map[string]string) {
	keys = map[string]string{
		"2captcha":    cfg.Captcha2CaptchaAPIKey,
		"capsolver":   cfg.CaptchaCapSolverAPIKey,
		"anticaptcha": cfg.CaptchaAntiCaptchaAPIKey,
		"9kw":         cfg.Captcha9kwAPIKey,
	}
	baseURLs = map[string]string{
		"2captcha":    cfg.Captcha2CaptchaBaseURL,
		"capsolver":   cfg.CaptchaCapSolverBaseURL,
		"anticaptcha": cfg.CaptchaAntiCaptchaBaseURL,
		"9kw":         cfg.Captcha9kwBaseURL,
	}
	return keys, baseURLs
}

// newCaptchaChain builds the external CAPTCHA solver chain from configuration.
//
// The chain is built even when CAPTCHA_FALLBACK_ENABLED is off. In that case it
// has no providers of its own and never contacts one; it exists so that a
// request carrying its own captchaSolver and captchaApiKey can still be served,
// and so the provider base URL overrides apply to that request too.
func newCaptchaChain(cfg *config.Config) *captcha.SolverChain {
	keys, baseURLs := captchaProviderSettings(cfg)
	enabled := cfg.HasCaptchaFallback()

	// Build the server's own providers in priority order using the registry.
	var providers []captcha.CaptchaSolver
	if enabled {
		for _, name := range captcha.BuildPriorityOrder(cfg.CaptchaPrimaryProvider, captcha.Available()) {
			apiKey := keys[name]
			if apiKey == "" {
				continue
			}
			factory := captcha.GetFactory(name)
			if factory == nil {
				continue
			}
			provider := factory(captcha.ProviderOptions{
				APIKey:  apiKey,
				Timeout: cfg.CaptchaSolverTimeout,
				BaseURL: baseURLs[name],
			})
			if provider.IsConfigured() {
				providers = append(providers, provider)
				log.Debug().Str("provider", name).Msg("CAPTCHA provider registered")
			}
		}
	}

	return captcha.NewSolverChain(captcha.SolverChainConfig{
		NativeAttempts:    cfg.CaptchaNativeAttempts,
		Providers:         providers,
		Metrics:           captcha.NewMetrics(),
		FallbackEnabled:   enabled && len(providers) > 0,
		MaxExternalSolves: cfg.CaptchaMaxExternalSolves,
		ProviderTimeout:   cfg.CaptchaSolverTimeout,
		BaseURLs:          baseURLs,
	})
}

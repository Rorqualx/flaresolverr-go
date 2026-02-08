// Package captcha provides external CAPTCHA solver integration for Turnstile challenges.
// It supports multiple providers (2Captcha, CapSolver) with automatic fallback.
package captcha

import (
	"context"
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// CaptchaSolver defines the interface for external CAPTCHA solving providers.
type CaptchaSolver interface {
	// Name returns the provider name (e.g., "2captcha", "capsolver").
	Name() string

	// SolveTurnstile attempts to solve a Turnstile CAPTCHA challenge.
	// Returns the solution token or an error.
	SolveTurnstile(ctx context.Context, req *TurnstileRequest) (*TurnstileResult, error)

	// Balance retrieves the current account balance from the provider.
	Balance(ctx context.Context) (float64, error)

	// IsConfigured returns true if the provider has valid API credentials.
	IsConfigured() bool
}

// TurnstileRequest contains the parameters needed to solve a Turnstile challenge.
type TurnstileRequest struct {
	SiteKey   string // The Turnstile sitekey (data-sitekey attribute)
	PageURL   string // The URL of the page containing the Turnstile
	UserAgent string // The user agent to use for solving
	Action    string // Optional action parameter
	CData     string // Optional cData parameter
}

// TurnstileResult contains the solution from a CAPTCHA solver.
type TurnstileResult struct {
	Token     string        // The solution token to inject
	SolveTime time.Duration // How long the solve took
	Cost      float64       // Cost in USD for this solve
	Provider  string        // Which provider solved it
}

// SolverChain orchestrates native and external CAPTCHA solving.
// It tracks attempts and determines when to fall back to external solvers.
type SolverChain struct {
	nativeAttempts int             // Number of native attempts before fallback
	providers      []CaptchaSolver // External solver providers in order of preference
	metrics        *Metrics        // Usage metrics tracking
	enabled        bool            // Whether external fallback is enabled
}

// SolverChainConfig contains configuration for the SolverChain.
type SolverChainConfig struct {
	NativeAttempts  int             // Native attempts before fallback (default: 3)
	Providers       []CaptchaSolver // External providers in priority order
	Metrics         *Metrics        // Metrics tracker (optional)
	FallbackEnabled bool            // Whether external fallback is enabled
}

// NewSolverChain creates a new SolverChain with the given configuration.
func NewSolverChain(cfg SolverChainConfig) *SolverChain {
	nativeAttempts := cfg.NativeAttempts
	if nativeAttempts < 1 {
		nativeAttempts = 3
	}
	if nativeAttempts > 10 {
		nativeAttempts = 10
	}

	return &SolverChain{
		nativeAttempts: nativeAttempts,
		providers:      cfg.Providers,
		metrics:        cfg.Metrics,
		enabled:        cfg.FallbackEnabled,
	}
}

// ShouldFallback returns true if native solving has been exhausted
// and external solving should be attempted.
func (c *SolverChain) ShouldFallback(attempts int) bool {
	if !c.enabled {
		return false
	}
	return attempts >= c.nativeAttempts
}

// IsEnabled returns true if external CAPTCHA solving is enabled.
func (c *SolverChain) IsEnabled() bool {
	return c.enabled
}

// NativeAttempts returns the configured number of native attempts.
func (c *SolverChain) NativeAttempts() int {
	return c.nativeAttempts
}

// HasProviders returns true if at least one provider is configured.
func (c *SolverChain) HasProviders() bool {
	for _, p := range c.providers {
		if p.IsConfigured() {
			return true
		}
	}
	return false
}

// SolveResult contains the outcome of a CAPTCHA solve attempt.
type SolveResult struct {
	Token     string        // The solution token
	Provider  string        // Which provider solved it ("native" or provider name)
	SolveTime time.Duration // How long the solve took
	Cost      float64       // Cost in USD (0 for native)
	Injected  bool          // Whether the token was successfully injected
}

// Solve attempts to solve the Turnstile challenge using external providers.
// This should only be called after native solving has been exhausted.
//
// The function:
// 1. Extracts the sitekey from the page
// 2. Tries each provider in order until one succeeds
// 3. Injects the token into the page
// 4. Records metrics
func (c *SolverChain) Solve(ctx context.Context, page *rod.Page, pageURL, userAgent string) (*SolveResult, error) {
	if !c.enabled {
		return nil, fmt.Errorf("external CAPTCHA solving is not enabled")
	}

	startTime := time.Now()

	// Extract sitekey from page
	sitekey, err := ExtractTurnstileSitekey(page)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract Turnstile sitekey")
		return nil, fmt.Errorf("failed to extract sitekey: %w", err)
	}

	log.Info().
		Str("sitekey", sitekey[:min(10, len(sitekey))]+"...").
		Str("url", pageURL).
		Msg("Attempting external CAPTCHA solve")

	req := &TurnstileRequest{
		SiteKey:   sitekey,
		PageURL:   pageURL,
		UserAgent: userAgent,
	}

	// Try each provider in order
	var lastErr error
	for _, provider := range c.providers {
		if !provider.IsConfigured() {
			continue
		}

		providerStart := time.Now()
		result, err := provider.SolveTurnstile(ctx, req)
		providerDuration := time.Since(providerStart)

		if err != nil {
			log.Warn().
				Err(err).
				Str("provider", provider.Name()).
				Dur("duration", providerDuration).
				Msg("External solver failed, trying next provider")
			lastErr = err

			// Record failed attempt
			if c.metrics != nil {
				c.metrics.RecordAttempt(provider.Name(), false, 0, providerDuration)
			}
			continue
		}

		// Success - inject the token
		log.Info().
			Str("provider", provider.Name()).
			Dur("solve_time", result.SolveTime).
			Float64("cost", result.Cost).
			Msg("External solver succeeded")

		injected := false
		if err := InjectTurnstileToken(ctx, page, result.Token); err != nil {
			log.Warn().Err(err).Msg("Failed to inject token, returning token anyway")
		} else {
			injected = true
			log.Debug().Msg("Token injected successfully")
		}

		// Record successful attempt
		if c.metrics != nil {
			c.metrics.RecordAttempt(provider.Name(), true, result.Cost, result.SolveTime)
		}

		return &SolveResult{
			Token:     result.Token,
			Provider:  provider.Name(),
			SolveTime: time.Since(startTime),
			Cost:      result.Cost,
			Injected:  injected,
		}, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}

	return nil, types.ErrCaptchaNoProviders
}

// GetMetrics returns the current metrics for all providers.
func (c *SolverChain) GetMetrics() map[string]interface{} {
	if c.metrics == nil {
		return nil
	}
	return c.metrics.ToJSON()
}


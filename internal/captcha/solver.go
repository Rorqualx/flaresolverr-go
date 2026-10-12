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

const (
	// DefaultMaxExternalSolves is how many paid tasks one request may create
	// when the operator enabled the fallback and did not say otherwise.
	DefaultMaxExternalSolves = 1

	// MaxExternalSolvesLimit is the hard ceiling for the per-request budget.
	MaxExternalSolvesLimit = 3

	defaultNativeAttempts = 3
	maxNativeAttempts     = 10
)

// CaptchaSolver defines the interface for external CAPTCHA solving providers.
type CaptchaSolver interface {
	// Name returns the provider name (e.g., "2captcha", "capsolver").
	Name() string

	// SolveTurnstile attempts to solve a Turnstile CAPTCHA challenge.
	// Returns the solution token or an error.
	SolveTurnstile(ctx context.Context, req *TurnstileRequest) (*TurnstileResult, error)

	// SolveHCaptcha attempts to solve an hCaptcha challenge.
	// Returns the solution token or an error.
	SolveHCaptcha(ctx context.Context, req *HCaptchaRequest) (*CaptchaResult, error)

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
	PageData  string // Optional chlPageData — required for Cloudflare managed challenges
}

// HCaptchaRequest contains the parameters needed to solve an hCaptcha challenge.
type HCaptchaRequest struct {
	SiteKey   string // The hCaptcha sitekey (data-sitekey attribute)
	PageURL   string // The URL of the page containing the hCaptcha
	UserAgent string // The user agent to use for solving
}

// CaptchaResult contains the solution from a CAPTCHA solver (generic).
type CaptchaResult = TurnstileResult

// TurnstileResult contains the solution from a CAPTCHA solver.
type TurnstileResult struct {
	Token     string        // The solution token to inject
	UserAgent string        // The User-Agent the provider's worker solved with, if it reported one
	SolveTime time.Duration // How long the solve took
	Cost      float64       // Cost in USD for this solve
	Provider  string        // Which provider solved it
}

// SolverChain holds the server-wide external solving configuration. It buys
// nothing itself: every request gets its own RequestSolver (NewRequest), which
// carries that request's providers and budget.
type SolverChain struct {
	nativeAttempts  int               // Number of native attempts before fallback
	providers       []CaptchaSolver   // External solver providers in order of preference
	metrics         *Metrics          // Usage metrics tracking
	enabled         bool              // Whether external fallback is enabled
	maxSolves       int               // Paid tasks one request may create
	providerTimeout time.Duration     // Solve timeout for providers built from a per-request key
	baseURLs        map[string]string // Provider base URL overrides, by provider name
	pollInterval    time.Duration     // Poll interval override for per-request providers (testing)
}

// SolverChainConfig contains configuration for the SolverChain.
type SolverChainConfig struct {
	NativeAttempts  int             // Native attempts before fallback (default: 3)
	Providers       []CaptchaSolver // External providers in priority order
	Metrics         *Metrics        // Metrics tracker (optional)
	FallbackEnabled bool            // Whether external fallback is enabled

	// MaxExternalSolves is how many paid tasks one request may create with the
	// server's own keys. Zero buys nothing; values above MaxExternalSolvesLimit
	// are clamped.
	MaxExternalSolves int

	// Settings for providers built on the fly from a per-request API key.
	ProviderTimeout time.Duration     // Solve timeout (zero selects each provider's default)
	BaseURLs        map[string]string // Base URL overrides by provider name
	PollInterval    time.Duration     // Poll interval override (testing)
}

// NewSolverChain creates a new SolverChain with the given configuration.
func NewSolverChain(cfg SolverChainConfig) *SolverChain {
	nativeAttempts := cfg.NativeAttempts
	if nativeAttempts < 1 {
		nativeAttempts = defaultNativeAttempts
	}
	if nativeAttempts > maxNativeAttempts {
		nativeAttempts = maxNativeAttempts
	}

	baseURLs := make(map[string]string, len(cfg.BaseURLs))
	for name, baseURL := range cfg.BaseURLs {
		if baseURL != "" {
			baseURLs[name] = baseURL
		}
	}

	return &SolverChain{
		nativeAttempts:  nativeAttempts,
		providers:       cfg.Providers,
		metrics:         cfg.Metrics,
		enabled:         cfg.FallbackEnabled,
		maxSolves:       ClampMaxExternalSolves(cfg.MaxExternalSolves),
		providerTimeout: cfg.ProviderTimeout,
		baseURLs:        baseURLs,
		pollInterval:    cfg.PollInterval,
	}
}

// ClampMaxExternalSolves bounds a per-request budget to [0, MaxExternalSolvesLimit].
func ClampMaxExternalSolves(n int) int {
	if n < 0 {
		return 0
	}
	if n > MaxExternalSolvesLimit {
		return MaxExternalSolvesLimit
	}
	return n
}

// ShouldFallback reports whether the server-wide configuration would hand a
// Turnstile to an external solver after this many native attempts. It knows
// nothing about any one request's budget or policy; the solve loop asks the
// request's RequestSolver instead.
func (c *SolverChain) ShouldFallback(attempts int) bool {
	return c.IsEnabled() && attempts >= c.nativeAttempts
}

// IsEnabled returns true if external CAPTCHA solving with the server's own keys
// is enabled.
func (c *SolverChain) IsEnabled() bool {
	return c != nil && c.enabled
}

// NativeAttempts returns the configured number of native attempts.
func (c *SolverChain) NativeAttempts() int {
	if c == nil {
		return defaultNativeAttempts
	}
	return c.nativeAttempts
}

// MaxExternalSolves returns the per-request budget for the server's own keys.
func (c *SolverChain) MaxExternalSolves() int {
	if c == nil {
		return 0
	}
	return c.maxSolves
}

// GetProviders returns the list of configured CAPTCHA solver providers.
func (c *SolverChain) GetProviders() []CaptchaSolver {
	if c == nil {
		return nil
	}
	return c.providers
}

// HasProviders returns true if at least one provider is configured.
func (c *SolverChain) HasProviders() bool {
	for _, p := range c.GetProviders() {
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

// Metrics returns the usage metrics tracker, or nil if none was configured.
func (c *SolverChain) Metrics() *Metrics {
	if c == nil {
		return nil
	}
	return c.metrics
}

// GetMetrics returns the current metrics for all providers.
func (c *SolverChain) GetMetrics() map[string]interface{} {
	if c == nil || c.metrics == nil {
		return nil
	}
	return c.metrics.ToJSON()
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

	// Parameters captured live from the turnstile.render() call are used as a
	// set (managed challenges expose sitekey/action/cData/chlPageData only
	// there). Only when nothing was captured is the DOM consulted, and then
	// action and cData come from the same widget element as the sitekey.
	req := &TurnstileRequest{PageURL: pageURL, UserAgent: userAgent}
	captured, hasCaptured := ReadCapturedChallengeParams(ctx, page)
	if hasCaptured && captured.SiteKey != "" {
		log.Debug().Str("source", "render_intercept").Msg("Using intercepted Turnstile params")
		req.SiteKey = captured.SiteKey
		req.Action = captured.Action
		req.CData = captured.CData
		req.PageData = captured.PageData
	} else {
		hasCaptured = false
		widget, err := ExtractTurnstileWidget(ctx, page)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to extract Turnstile sitekey")
			return nil, fmt.Errorf("failed to extract sitekey: %w", err)
		}
		req.SiteKey = widget.SiteKey
		req.Action = widget.Action
		req.CData = widget.CData
	}
	sitekey := req.SiteKey

	log.Info().
		Str("sitekey", sitekey[:min(10, len(sitekey))]+"...").
		Str("url", pageURL).
		Bool("managed", req.PageData != "").
		Bool("intercepted", hasCaptured).
		Msg("Attempting external CAPTCHA solve")

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
		// Managed challenges complete through the captured render() callback;
		// try that first, then fall back to the generic textarea/callback methods.
		if InjectCapturedCallback(ctx, page, result.Token) {
			injected = true
		} else if err := InjectTurnstileToken(ctx, page, result.Token); err != nil {
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

// SolveHCaptcha attempts to solve an hCaptcha challenge using external providers.
// This follows the same fallback pattern as Solve but uses hCaptcha extraction/injection.
func (c *SolverChain) SolveHCaptcha(ctx context.Context, page *rod.Page, pageURL, userAgent string) (*SolveResult, error) {
	if !c.enabled {
		return nil, fmt.Errorf("external CAPTCHA solving is not enabled")
	}

	startTime := time.Now()

	// Extract hCaptcha sitekey from page
	sitekey, err := ExtractHCaptchaSitekey(ctx, page)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract hCaptcha sitekey")
		return nil, fmt.Errorf("failed to extract hCaptcha sitekey: %w", err)
	}

	log.Info().
		Str("sitekey", sitekey[:min(10, len(sitekey))]+"...").
		Str("url", pageURL).
		Msg("Attempting external hCaptcha solve")

	req := &HCaptchaRequest{
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
		result, err := provider.SolveHCaptcha(ctx, req)
		providerDuration := time.Since(providerStart)

		if err != nil {
			log.Warn().
				Err(err).
				Str("provider", provider.Name()).
				Dur("duration", providerDuration).
				Msg("External hCaptcha solver failed, trying next provider")
			lastErr = err

			if c.metrics != nil {
				c.metrics.RecordAttempt(provider.Name(), false, 0, providerDuration)
			}
			continue
		}

		log.Info().
			Str("provider", provider.Name()).
			Dur("solve_time", result.SolveTime).
			Float64("cost", result.Cost).
			Msg("External hCaptcha solver succeeded")

		injected := false
		if err := InjectHCaptchaToken(ctx, page, result.Token); err != nil {
			log.Warn().Err(err).Msg("Failed to inject hCaptcha token, returning token anyway")
		} else {
			injected = true
			log.Debug().Msg("hCaptcha token injected successfully")
		}

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
		return nil, fmt.Errorf("all providers failed for hCaptcha, last error: %w", lastErr)
	}

	return nil, types.ErrCaptchaNoProviders
}

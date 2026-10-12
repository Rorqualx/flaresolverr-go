package captcha

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	// perRequestKeyBudget is how many tasks a request may create with an API key
	// it supplied itself.
	perRequestKeyBudget = 1

	// minExternalSolveWindow is how much of the request's time must be left
	// for a task to be worth creating. Providers are first polled seconds after
	// creation and rarely answer sooner.
	minExternalSolveWindow = 10 * time.Second

	kindTurnstile = "turnstile"
	kindHCaptcha  = "hcaptcha"
)

// RequestPolicy is what one API request asked for regarding external solving.
type RequestPolicy struct {
	// Solver is "" (use the server's providers), "none" (buy nothing), or a
	// provider name.
	Solver string

	// APIKey is the request's own key for Solver. SECURITY: it is the caller's
	// secret. It is handed to one provider instance that lives as long as the
	// request and must never be logged, cached or put into an error.
	APIKey string
}

// RequestSolver buys external solves on behalf of ONE request. It holds that
// request's providers, how many paid tasks it may still create, and whether a
// paid task has already timed out. It is safe for concurrent use, and every
// method is safe on a nil receiver (which buys nothing).
type RequestSolver struct {
	chain     *SolverChain
	providers []CaptchaSolver
	secret    string // per-request key, kept only to scrub it from messages

	mu        sync.Mutex
	remaining int                 // paid tasks this request may still create
	stopped   bool                // a paid task timed out; buy nothing more
	refused   map[string]struct{} // "<kind>/<provider>" pairs that turned the request down
}

// NewRequest resolves what the request is allowed to buy:
//
//   - Solver "none": nothing.
//   - Solver plus APIKey: that provider with that key, one task, whether or not
//     the server-side fallback is enabled.
//   - Solver alone: the server's provider of that name, if the fallback is on.
//   - neither: the server's providers in priority order, if the fallback is on.
//
// With the fallback off and no key in the request it returns a solver that
// never contacts a provider.
func (c *SolverChain) NewRequest(policy RequestPolicy) *RequestSolver {
	if c == nil {
		return nil
	}
	r := &RequestSolver{chain: c, refused: make(map[string]struct{})}

	switch {
	case policy.Solver == types.CaptchaSolverNone:
		// External solving explicitly forbidden for this request.

	case policy.Solver != "" && policy.APIKey != "":
		factory := GetFactory(policy.Solver)
		if factory == nil {
			break
		}
		r.providers = []CaptchaSolver{factory(ProviderOptions{
			APIKey:       policy.APIKey,
			Timeout:      c.providerTimeout,
			BaseURL:      c.baseURLs[policy.Solver],
			PollInterval: c.pollInterval,
		})}
		r.remaining = perRequestKeyBudget
		r.secret = policy.APIKey

	case !c.enabled:
		// Nothing was opted into: no purchase.

	default:
		for _, provider := range c.providers {
			if !provider.IsConfigured() {
				continue
			}
			if policy.Solver != "" && provider.Name() != policy.Solver {
				continue
			}
			r.providers = append(r.providers, provider)
		}
		r.remaining = c.maxSolves
	}

	if len(r.providers) == 0 {
		r.remaining = 0
	}
	return r
}

// Active reports whether this request could still buy an external solve.
func (r *RequestSolver) Active() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activeLocked()
}

func (r *RequestSolver) activeLocked() bool {
	return len(r.providers) > 0 && r.remaining > 0 && !r.stopped
}

// NativeAttempts returns how many native attempts precede an external solve.
func (r *RequestSolver) NativeAttempts() int {
	if r == nil {
		return defaultNativeAttempts
	}
	return r.chain.NativeAttempts()
}

// ShouldFallback returns true if native Turnstile solving has been exhausted and
// this request may still buy an external solve for it.
func (r *RequestSolver) ShouldFallback(attempts int) bool {
	return r.canSolve(kindTurnstile) && attempts >= r.NativeAttempts()
}

// CanSolveHCaptcha reports whether this request may still buy an hCaptcha solve.
func (r *RequestSolver) CanSolveHCaptcha() bool {
	return r.canSolve(kindHCaptcha)
}

// Remaining returns how many paid tasks this request may still create.
func (r *RequestSolver) Remaining() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return 0
	}
	return r.remaining
}

// canSolve reports whether budget remains and at least one provider has not
// already turned this kind of captcha down for this request.
func (r *RequestSolver) canSolve(kind string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.activeLocked() {
		return false
	}
	for _, provider := range r.providers {
		if _, refused := r.refused[kind+"/"+provider.Name()]; !refused {
			return true
		}
	}
	return false
}

// acquire takes one unit of budget for a provider, or reports why it cannot.
func (r *RequestSolver) acquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.activeLocked() {
		return false
	}
	r.remaining--
	return true
}

// refund returns the unit taken for a provider that definitively created no
// task, and remembers the refusal so the same question is not asked again.
func (r *RequestSolver) refund(kind, provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remaining++
	r.refused[kind+"/"+provider] = struct{}{}
}

func (r *RequestSolver) isRefused(kind, provider string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, refused := r.refused[kind+"/"+provider]
	return refused
}

// stop latches the request: a task was paid for and did not deliver in time.
func (r *RequestSolver) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
}

// buy asks the request's providers, in order, for one solution.
//
// Budget accounting, counted in tasks created at a provider:
//   - a provider that definitively refuses (unsupported captcha, bad key, empty
//     balance, or no request sent at all) costs nothing and the next is tried;
//   - once a task was created and timed out, nothing more is bought for this
//     request, from anyone;
//   - any other failure after a task was (or may have been) created keeps its
//     unit spent, and the next provider is tried only if budget remains.
func (r *RequestSolver) buy(ctx context.Context, kind string, solve func(CaptchaSolver) (*TurnstileResult, error)) (*TurnstileResult, error) {
	if r == nil || len(r.providers) == 0 {
		return nil, types.ErrCaptchaNoProviders
	}
	// A task created moments before the request's deadline is paid for and
	// then abandoned: the first result poll is seconds away.
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < minExternalSolveWindow {
		return nil, fmt.Errorf("%w (%s left)", types.ErrCaptchaInsufficientTime, time.Until(deadline).Round(time.Second))
	}

	var lastErr error
	for _, provider := range r.providers {
		name := provider.Name()
		if r.isRefused(kind, name) {
			continue
		}
		if !r.acquire() {
			if lastErr != nil {
				return nil, fmt.Errorf("%w (last provider error: %w)", types.ErrCaptchaBudgetExhausted, lastErr)
			}
			return nil, types.ErrCaptchaBudgetExhausted
		}

		started := time.Now()
		result, err := solve(provider)
		elapsed := time.Since(started)
		if err == nil && (result == nil || result.Token == "") {
			err = types.NewCaptchaRejectedError(name, "EMPTY_SOLUTION", "provider returned no token")
		}

		if err == nil {
			if result.Provider == "" {
				result.Provider = name
			}
			r.record(name, true, true, result.Cost, elapsed, "")
			log.Info().
				Str("provider", name).
				Str("captcha", kind).
				Dur("solve_time", result.SolveTime).
				Float64("cost", result.Cost).
				Int("budget_remaining", r.Remaining()).
				Msg("External solver succeeded")
			return result, nil
		}

		err = r.scrubError(err)
		lastErr = err
		created := TaskCreated(err)
		r.record(name, false, created, 0, elapsed, err.Error())

		switch {
		case !created:
			r.refund(kind, name)
			log.Warn().Err(err).Str("provider", name).Str("captcha", kind).
				Msg("External solver refused the request before creating a task, trying next provider")
		case errors.Is(err, types.ErrCaptchaSolverTimeout) || ctx.Err() != nil:
			r.stop()
			log.Warn().Err(err).Str("provider", name).Str("captcha", kind).Dur("duration", elapsed).
				Msg("External solver timed out on a created task; no further external solves for this request")
			return nil, err
		default:
			log.Warn().Err(err).Str("provider", name).Str("captcha", kind).Dur("duration", elapsed).
				Msg("External solver failed after creating a task")
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, types.ErrCaptchaNoProviders
}

// record updates the shared usage metrics for one provider call.
func (r *RequestSolver) record(provider string, success, created bool, cost float64, elapsed time.Duration, errMsg string) {
	metrics := r.chain.Metrics()
	if metrics == nil {
		return
	}
	metrics.RecordAttempt(provider, success, cost, elapsed)
	if created {
		metrics.RecordTask(provider)
	}
	if errMsg != "" {
		metrics.RecordError(provider, errMsg)
	}
}

// scrubbedError carries a message with the per-request key removed while
// keeping the original error chain for errors.Is/As.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// scrubError guarantees the per-request key cannot leave through an error
// message, whatever a provider chose to echo back.
func (r *RequestSolver) scrubError(err error) error {
	if r.secret == "" || err == nil {
		return err
	}
	msg := err.Error()
	clean := scrub(msg, r.secret)
	if clean == msg {
		return err
	}
	return &scrubbedError{msg: clean, err: err}
}

// SolveTurnstile buys a Turnstile solution and injects it into the page.
// This should only be called after native solving has been exhausted.
// userAgent must be the User-Agent the page is actually using for this request.
func (r *RequestSolver) SolveTurnstile(ctx context.Context, page *rod.Page, pageURL, userAgent string) (*SolveResult, error) {
	if !r.canSolve(kindTurnstile) {
		return nil, r.inactiveError()
	}
	page = page.Context(ctx)
	startTime := time.Now()

	req, intercepted, err := buildTurnstileRequest(ctx, page, pageURL, userAgent)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract Turnstile sitekey")
		return nil, fmt.Errorf("failed to extract sitekey: %w", err)
	}

	log.Info().
		Str("sitekey", sitekeyPreview(req.SiteKey)).
		Str("url", pageURL).
		Bool("managed", req.PageData != "").
		Bool("intercepted", intercepted).
		Msg("Attempting external CAPTCHA solve")

	result, err := r.buy(ctx, kindTurnstile, func(provider CaptchaSolver) (*TurnstileResult, error) {
		return provider.SolveTurnstile(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	warnOnAgentMismatch(result, userAgent)

	// Managed challenges complete through the captured render() callback;
	// try that first, then fall back to the response field and page callbacks.
	injected := InjectCapturedCallback(ctx, page, result.Token)
	if !injected {
		if err := InjectTurnstileToken(ctx, page, result.Token); err != nil {
			log.Warn().Err(err).Msg("Failed to inject token, returning token anyway")
		} else {
			injected = true
		}
	}

	return &SolveResult{
		Token:     result.Token,
		Provider:  result.Provider,
		SolveTime: time.Since(startTime),
		Cost:      result.Cost,
		Injected:  injected,
	}, nil
}

// SolveHCaptcha buys an hCaptcha solution and injects it into the page. It draws
// on the same per-request budget as SolveTurnstile.
func (r *RequestSolver) SolveHCaptcha(ctx context.Context, page *rod.Page, pageURL, userAgent string) (*SolveResult, error) {
	if !r.canSolve(kindHCaptcha) {
		return nil, r.inactiveError()
	}
	page = page.Context(ctx)
	startTime := time.Now()

	sitekey, err := ExtractHCaptchaSitekey(ctx, page)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract hCaptcha sitekey")
		return nil, fmt.Errorf("failed to extract hCaptcha sitekey: %w", err)
	}

	log.Info().
		Str("sitekey", sitekeyPreview(sitekey)).
		Str("url", pageURL).
		Msg("Attempting external hCaptcha solve")

	req := &HCaptchaRequest{SiteKey: sitekey, PageURL: pageURL, UserAgent: userAgent}
	result, err := r.buy(ctx, kindHCaptcha, func(provider CaptchaSolver) (*TurnstileResult, error) {
		return provider.SolveHCaptcha(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	warnOnAgentMismatch(result, userAgent)

	injected := true
	if err := InjectHCaptchaToken(ctx, page, result.Token); err != nil {
		injected = false
		log.Warn().Err(err).Msg("Failed to inject hCaptcha token, returning token anyway")
	}

	return &SolveResult{
		Token:     result.Token,
		Provider:  result.Provider,
		SolveTime: time.Since(startTime),
		Cost:      result.Cost,
		Injected:  injected,
	}, nil
}

// inactiveError explains why this request cannot buy a solve.
func (r *RequestSolver) inactiveError() error {
	if r == nil || len(r.providers) == 0 {
		return types.ErrCaptchaNoProviders
	}
	return types.ErrCaptchaBudgetExhausted
}

// buildTurnstileRequest gathers the Turnstile parameters for a provider.
//
// Parameters captured live from the turnstile.render() call are authoritative
// and are used as a set: managed challenges expose sitekey/action/cData/
// chlPageData only there. Only when nothing was captured is the DOM consulted,
// and then action and cData come from the same widget element as the sitekey.
func buildTurnstileRequest(ctx context.Context, page *rod.Page, pageURL, userAgent string) (*TurnstileRequest, bool, error) {
	req := &TurnstileRequest{PageURL: pageURL, UserAgent: userAgent}

	if captured, ok := ReadCapturedChallengeParams(ctx, page); ok && captured.SiteKey != "" {
		log.Debug().Str("source", "render_intercept").Msg("Using intercepted Turnstile params")
		req.SiteKey = captured.SiteKey
		req.Action = captured.Action
		req.CData = captured.CData
		req.PageData = captured.PageData
		return req, true, nil
	}

	widget, err := ExtractTurnstileWidget(ctx, page)
	if err != nil {
		return nil, false, err
	}
	req.SiteKey = widget.SiteKey
	req.Action = widget.Action
	req.CData = widget.CData
	return req, false, nil
}

// warnOnAgentMismatch logs when the provider solved with a different User-Agent
// than the page uses. Cloudflare binds a token to the User-Agent that earned
// it, so a mismatch is the likely reason an injected token is then rejected.
// The page's User-Agent is deliberately left alone mid-challenge.
func warnOnAgentMismatch(result *TurnstileResult, pageAgent string) {
	if result.UserAgent == "" || pageAgent == "" || result.UserAgent == pageAgent {
		return
	}
	log.Warn().
		Str("provider", result.Provider).
		Str("provider_user_agent", result.UserAgent).
		Str("page_user_agent", pageAgent).
		Msg("Captcha provider solved with a different User-Agent than the page; the token may be rejected")
}

package solver

import (
	"testing"

	"github.com/Rorqualx/flaresolverr-go/internal/captcha"
)

const serverUserAgent = "Mozilla/5.0 (server default) Chrome/140"

// enabledChain returns a chain with the server-side fallback on. Its provider
// points nowhere reachable; these tests never let it be called.
func enabledChain(maxSolves int) *captcha.SolverChain {
	return captcha.NewSolverChain(captcha.SolverChainConfig{
		Providers: []captcha.CaptchaSolver{captcha.NewTwoCaptchaSolver(captcha.TwoCaptchaConfig{
			APIKey:  "server-side-value",
			BaseURL: "http://127.0.0.1:1",
		})},
		Metrics:           captcha.NewMetrics(),
		FallbackEnabled:   true,
		MaxExternalSolves: maxSolves,
	})
}

// TestExternalSolver_RequestPolicy checks which requests may buy an external
// solve, as seen from the solver: this is what gates both the render()
// interceptor and the fallback inside the solve loop.
func TestExternalSolver_RequestPolicy(t *testing.T) {
	disabled := captcha.NewSolverChain(captcha.SolverChainConfig{Metrics: captcha.NewMetrics()})

	tests := []struct {
		name       string
		chain      *captcha.SolverChain
		opts       SolveOptions
		wantActive bool
		wantBudget int
	}{
		{name: "no chain at all", chain: nil},
		{name: "fallback not enabled", chain: disabled},
		{name: "fallback not enabled, provider named", chain: disabled, opts: SolveOptions{CaptchaSolver: "2captcha"}},
		{
			name: "fallback not enabled, request brings its own key", chain: disabled,
			opts:       SolveOptions{CaptchaSolver: "2captcha", CaptchaApiKey: "request-scoped-value"},
			wantActive: true, wantBudget: 1,
		},
		{name: "fallback enabled", chain: enabledChain(1), wantActive: true, wantBudget: 1},
		{name: "fallback enabled, budget of two", chain: enabledChain(2), wantActive: true, wantBudget: 2},
		{name: "fallback enabled, budget of zero", chain: enabledChain(0)},
		{name: "fallback enabled, request says none", chain: enabledChain(3), opts: SolveOptions{CaptchaSolver: "none"}},
		{
			name: "fallback enabled, request names the server's provider", chain: enabledChain(2),
			opts: SolveOptions{CaptchaSolver: "2captcha"}, wantActive: true, wantBudget: 2,
		},
		{name: "fallback enabled, request names another provider", chain: enabledChain(2), opts: SolveOptions{CaptchaSolver: "capsolver"}},
		{
			name: "fallback enabled, request key overrides the budget to one", chain: enabledChain(3),
			opts:       SolveOptions{CaptchaSolver: "capsolver", CaptchaApiKey: "request-scoped-value"},
			wantActive: true, wantBudget: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(nil, serverUserAgent)
			s.SetSolverChain(tt.chain)
			opts := tt.opts
			opts.URL = "https://example.com"

			external := s.externalSolver(&opts)
			if got := external.Active(); got != tt.wantActive {
				t.Errorf("Active() = %v, want %v", got, tt.wantActive)
			}
			if got := external.Remaining(); got != tt.wantBudget {
				t.Errorf("Remaining() = %d, want %d", got, tt.wantBudget)
			}
			if got := external.ShouldFallback(external.NativeAttempts()); got != tt.wantActive {
				t.Errorf("ShouldFallback(native attempts) = %v, want %v", got, tt.wantActive)
			}
			if external.ShouldFallback(external.NativeAttempts() - 1) {
				t.Error("ShouldFallback fired before native attempts were exhausted")
			}
		})
	}
}

// TestExternalSolver_OneBudgetPerRequest: the solve loop's parameters are
// built several times for one request (bodyless error path, main loop,
// reconnect bypass). They must all draw on the same allowance, while another
// request gets its own.
func TestExternalSolver_OneBudgetPerRequest(t *testing.T) {
	s := New(nil, serverUserAgent)
	s.SetSolverChain(enabledChain(1))

	first := &SolveOptions{URL: "https://example.com/a"}
	second := &SolveOptions{URL: "https://example.com/b"}

	a1 := s.newSolveParams(first, nil, nil).external
	a2 := s.newSolveParams(first, nil, nil).external
	a3 := s.externalSolver(first)
	b1 := s.newSolveParams(second, nil, nil).external

	if a1 == nil || a1 != a2 || a1 != a3 {
		t.Errorf("one request yielded different external solvers: %p %p %p", a1, a2, a3)
	}
	if b1 == nil || b1 == a1 {
		t.Error("two requests share one external solver (and so one budget)")
	}
}

func TestExternalSolver_NilSafe(t *testing.T) {
	s := New(nil, serverUserAgent)

	if got := s.externalSolver(nil); got != nil || got.Active() {
		t.Error("nil options must yield an inert solver")
	}
	sp := s.newSolveParams(&SolveOptions{URL: "https://example.com"}, nil, nil)
	if sp.external.Active() || sp.external.ShouldFallback(100) || sp.external.CanSolveHCaptcha() {
		t.Error("a solver without a chain must never want to buy")
	}
	if s.CaptchaStats() != nil {
		t.Error("CaptchaStats() without a chain must be nil")
	}

	s.SetSolverChain(enabledChain(1))
	if stats := s.CaptchaStats(); stats == nil || len(stats) != 0 {
		t.Errorf("CaptchaStats() = %v, want an empty map before any solve", stats)
	}
}

// TestSolveParams_ProviderGetsEffectiveUserAgent: the User-Agent handed to an
// external provider is the one the page really uses — the request's override
// when there is one — because Cloudflare binds the token to it.
func TestSolveParams_ProviderGetsEffectiveUserAgent(t *testing.T) {
	const override = "Mozilla/5.0 (request override) Chrome/141"
	s := New(nil, serverUserAgent)

	tests := []struct {
		name string
		opts SolveOptions
		want string
	}{
		{"server default", SolveOptions{}, serverUserAgent},
		{"request override", SolveOptions{UserAgent: override}, override},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			if got := s.newSolveParams(&opts, nil, nil).userAgent; got != tt.want {
				t.Errorf("solveParams.userAgent = %q, want %q", got, tt.want)
			}
		})
	}
}

package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// serverProvider builds one of the server's own providers against a fake.
func serverProvider(t *testing.T, name, baseURL string) CaptchaSolver {
	t.Helper()
	factory := GetFactory(name)
	if factory == nil {
		t.Fatalf("provider %q is not registered", name)
	}
	return factory(ProviderOptions{
		APIKey:       "server-side-value",
		Timeout:      testTimeout,
		BaseURL:      baseURL,
		PollInterval: testPollInterval,
	})
}

// buyTurnstile and buyHCaptcha do what RequestSolver.SolveTurnstile/SolveHCaptcha
// do once the page has been read: ask the request's providers for a token.
func buyTurnstile(r *RequestSolver, req *TurnstileRequest) (*TurnstileResult, error) {
	ctx := context.Background()
	return r.buy(ctx, kindTurnstile, func(p CaptchaSolver) (*TurnstileResult, error) {
		return p.SolveTurnstile(ctx, req)
	})
}

func buyHCaptcha(r *RequestSolver) (*TurnstileResult, error) {
	ctx := context.Background()
	req := &HCaptchaRequest{SiteKey: "10000000-ffff-ffff-ffff-000000000001", PageURL: "https://example.com"}
	return r.buy(ctx, kindHCaptcha, func(p CaptchaSolver) (*TurnstileResult, error) {
		return p.SolveHCaptcha(ctx, req)
	})
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs redirects the global logger, at its most verbose, into a buffer
// for the duration of the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	previous := log.Logger
	sink := &syncBuffer{}
	log.Logger = zerolog.New(sink).Level(zerolog.TraceLevel)
	t.Cleanup(func() { log.Logger = previous })
	return sink
}

// TestRequestSolver_NothingIsBoughtByDefault is the "no paid" guarantee: with
// the fallback not enabled and no key in the request, no provider is contacted,
// however the chain is asked.
func TestRequestSolver_NothingIsBoughtByDefault(t *testing.T) {
	fake := newFakeProvider(t)

	tests := []struct {
		name   string
		chain  SolverChainConfig
		policy RequestPolicy
	}{
		{
			name:  "zero-value chain",
			chain: SolverChainConfig{},
		},
		{
			name: "providers configured but fallback not enabled",
			chain: SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				MaxExternalSolves: 3,
			},
		},
		{
			name: "fallback not enabled and the request merely names a provider",
			chain: SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				MaxExternalSolves: 3,
			},
			policy: RequestPolicy{Solver: "2captcha"},
		},
		{
			name: "fallback enabled but the budget is zero",
			chain: SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				FallbackEnabled:   true,
				MaxExternalSolves: 0,
			},
		},
		{
			name: "fallback enabled and the request says none",
			chain: SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				FallbackEnabled:   true,
				MaxExternalSolves: 3,
			},
			policy: RequestPolicy{Solver: types.CaptchaSolverNone},
		},
		{
			name: "fallback enabled but the named provider is not one of the server's",
			chain: SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				FallbackEnabled:   true,
				MaxExternalSolves: 3,
			},
			policy: RequestPolicy{Solver: "capsolver"},
		},
		{
			name: "fallback enabled but the only provider has no key",
			chain: SolverChainConfig{
				Providers:         []CaptchaSolver{NewTwoCaptchaSolver(TwoCaptchaConfig{BaseURL: fake.URL})},
				FallbackEnabled:   true,
				MaxExternalSolves: 3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := NewSolverChain(tt.chain).NewRequest(tt.policy)

			if request.Active() {
				t.Error("Active() = true")
			}
			if request.ShouldFallback(100) {
				t.Error("ShouldFallback(100) = true")
			}
			if request.CanSolveHCaptcha() {
				t.Error("CanSolveHCaptcha() = true")
			}
			if request.Remaining() != 0 {
				t.Errorf("Remaining() = %d, want 0", request.Remaining())
			}
			if _, err := buyTurnstile(request, turnstileReq); err == nil {
				t.Error("buy(turnstile) succeeded")
			}
			if _, err := buyHCaptcha(request); err == nil {
				t.Error("buy(hcaptcha) succeeded")
			}
			// The public entry points refuse before touching the page (nil here).
			if _, err := request.SolveTurnstile(context.Background(), nil, "https://example.com", "ua"); err == nil {
				t.Error("SolveTurnstile succeeded")
			}
			if _, err := request.SolveHCaptcha(context.Background(), nil, "https://example.com", "ua"); err == nil {
				t.Error("SolveHCaptcha succeeded")
			}
		})
	}

	if fake.createCount() != 0 || fake.pollCount() != 0 {
		t.Errorf("provider was contacted: createTask=%d getTaskResult=%d, want 0 and 0", fake.createCount(), fake.pollCount())
	}
}

func TestRequestSolver_NilIsInert(t *testing.T) {
	var chain *SolverChain
	request := chain.NewRequest(RequestPolicy{Solver: "2captcha", APIKey: "anything"})
	if request != nil {
		t.Fatal("nil chain must yield a nil request solver")
	}
	if request.Active() || request.ShouldFallback(99) || request.CanSolveHCaptcha() || request.Remaining() != 0 {
		t.Error("nil request solver must be inert")
	}
	if request.NativeAttempts() != defaultNativeAttempts {
		t.Errorf("NativeAttempts() = %d", request.NativeAttempts())
	}
	if _, err := request.SolveTurnstile(context.Background(), nil, "u", "ua"); !errors.Is(err, types.ErrCaptchaNoProviders) {
		t.Errorf("SolveTurnstile error = %v, want ErrCaptchaNoProviders", err)
	}
	if _, err := buyHCaptcha(request); !errors.Is(err, types.ErrCaptchaNoProviders) {
		t.Errorf("buy error = %v, want ErrCaptchaNoProviders", err)
	}
	if chain.IsEnabled() || chain.HasProviders() || chain.Metrics() != nil || chain.MaxExternalSolves() != 0 {
		t.Error("nil chain must be inert")
	}
}

// TestRequestSolver_BudgetCapsCreatedTasks: the budget counts createTask calls
// for the whole request, across repeated solve-loop passes and across Turnstile
// and hCaptcha.
func TestRequestSolver_BudgetCapsCreatedTasks(t *testing.T) {
	tests := []struct {
		name        string
		configured  int
		wantCreates int
	}{
		{"default of one", DefaultMaxExternalSolves, 1},
		{"two", 2, 2},
		{"hard cap", 10, MaxExternalSolvesLimit},
		{"negative buys nothing", -1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t)
			request := NewSolverChain(SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				FallbackEnabled:   true,
				MaxExternalSolves: tt.configured,
			}).NewRequest(RequestPolicy{})

			// A solve loop that never sees the challenge clear keeps asking.
			var succeeded int
			for pass := 0; pass < 12; pass++ {
				var err error
				if pass%2 == 0 {
					_, err = buyTurnstile(request, turnstileReq)
				} else {
					_, err = buyHCaptcha(request)
				}
				if err == nil {
					succeeded++
					continue
				}
				if !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
					t.Fatalf("pass %d: error = %v, want ErrCaptchaBudgetExhausted", pass, err)
				}
			}

			if got := fake.createCount(); got != tt.wantCreates {
				t.Errorf("createTask calls = %d, want %d", got, tt.wantCreates)
			}
			if succeeded != tt.wantCreates {
				t.Errorf("successful buys = %d, want %d", succeeded, tt.wantCreates)
			}
			if request.Active() || request.ShouldFallback(100) || request.CanSolveHCaptcha() {
				t.Error("request still wants to buy after its budget is spent")
			}
		})
	}
}

func TestRequestSolver_BudgetIsPerRequest(t *testing.T) {
	fake := newFakeProvider(t)
	chain := NewSolverChain(SolverChainConfig{
		Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
		FallbackEnabled:   true,
		MaxExternalSolves: 1,
	})
	for i := 0; i < 3; i++ {
		request := chain.NewRequest(RequestPolicy{})
		if _, err := buyTurnstile(request, turnstileReq); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if _, err := buyTurnstile(request, turnstileReq); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
			t.Fatalf("request %d second buy: error = %v", i, err)
		}
	}
	if got := fake.createCount(); got != 3 {
		t.Errorf("createTask calls = %d, want one per request (3)", got)
	}
}

func TestRequestSolver_BudgetHoldsUnderConcurrency(t *testing.T) {
	fake := newFakeProvider(t)
	request := NewSolverChain(SolverChainConfig{
		Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
		FallbackEnabled:   true,
		MaxExternalSolves: 2,
	}).NewRequest(RequestPolicy{})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = buyTurnstile(request, turnstileReq)
		}()
	}
	wg.Wait()

	if got := fake.createCount(); got != 2 {
		t.Errorf("createTask calls = %d, want 2", got)
	}
}

func TestRequestSolver_ShouldFallbackWaitsForNativeAttempts(t *testing.T) {
	fake := newFakeProvider(t)
	request := NewSolverChain(SolverChainConfig{
		NativeAttempts:    3,
		Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
		FallbackEnabled:   true,
		MaxExternalSolves: 1,
	}).NewRequest(RequestPolicy{})

	for attempts, want := range map[int]bool{0: false, 2: false, 3: true, 9: true} {
		if got := request.ShouldFallback(attempts); got != want {
			t.Errorf("ShouldFallback(%d) = %v, want %v", attempts, got, want)
		}
	}
	if request.NativeAttempts() != 3 {
		t.Errorf("NativeAttempts() = %d, want 3", request.NativeAttempts())
	}
}

// TestRequestSolver_NamedProvider: captchaSolver without a key picks among the
// server's providers.
func TestRequestSolver_NamedProvider(t *testing.T) {
	twoCaptcha, antiCaptcha := newFakeProvider(t), newFakeProvider(t)
	chain := NewSolverChain(SolverChainConfig{
		Providers: []CaptchaSolver{
			serverProvider(t, "2captcha", twoCaptcha.URL),
			serverProvider(t, "anticaptcha", antiCaptcha.URL),
		},
		FallbackEnabled:   true,
		MaxExternalSolves: 1,
	})

	result, err := buyTurnstile(chain.NewRequest(RequestPolicy{Solver: "anticaptcha"}), turnstileReq)
	if err != nil {
		t.Fatalf("buy error = %v", err)
	}
	if result.Provider != "anticaptcha" {
		t.Errorf("Provider = %q, want anticaptcha", result.Provider)
	}
	if twoCaptcha.createCount() != 0 || antiCaptcha.createCount() != 1 {
		t.Errorf("createTask calls: 2captcha=%d anticaptcha=%d, want 0 and 1", twoCaptcha.createCount(), antiCaptcha.createCount())
	}
	if got := antiCaptcha.lastClientKey(t); got != "server-side-value" {
		t.Errorf("clientKey = %q, want the server's key", got)
	}
}

// TestRequestSolver_PerRequestKey: captchaSolver + captchaApiKey uses that
// provider with that key, for one task, even with the server fallback off.
func TestRequestSolver_PerRequestKey(t *testing.T) {
	const requestKey = "request-scoped-value-0001"

	for _, enabled := range []bool{false, true} {
		name := "fallback disabled"
		if enabled {
			name = "fallback enabled"
		}
		t.Run(name, func(t *testing.T) {
			own, serverSide := newFakeProvider(t), newFakeProvider(t)
			cfg := SolverChainConfig{
				FallbackEnabled:   enabled,
				MaxExternalSolves: 3,
				ProviderTimeout:   testTimeout,
				PollInterval:      testPollInterval,
				BaseURLs:          map[string]string{"2captcha": own.URL},
				Metrics:           NewMetrics(),
			}
			if enabled {
				cfg.Providers = []CaptchaSolver{serverProvider(t, "anticaptcha", serverSide.URL)}
			}
			chain := NewSolverChain(cfg)
			request := chain.NewRequest(RequestPolicy{Solver: "2captcha", APIKey: requestKey})

			if !request.Active() || request.Remaining() != perRequestKeyBudget {
				t.Fatalf("Active() = %v, Remaining() = %d; want active with budget %d", request.Active(), request.Remaining(), perRequestKeyBudget)
			}

			result, err := buyTurnstile(request, turnstileReq)
			if err != nil {
				t.Fatalf("buy error = %v", err)
			}
			if result.Provider != "2captcha" {
				t.Errorf("Provider = %q, want 2captcha", result.Provider)
			}
			if got := own.lastClientKey(t); got != requestKey {
				t.Errorf("provider received clientKey %q, want the request's key", got)
			}
			if serverSide.createCount() != 0 {
				t.Error("the server's own provider was used although the request brought a key")
			}

			// One task only, whatever CAPTCHA_MAX_EXTERNAL_SOLVES says.
			if _, err := buyTurnstile(request, turnstileReq); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
				t.Errorf("second buy error = %v, want ErrCaptchaBudgetExhausted", err)
			}
			if own.createCount() != 1 {
				t.Errorf("createTask calls = %d, want 1", own.createCount())
			}

			// The key must not have been kept on anything that outlives the request.
			for _, provider := range chain.GetProviders() {
				if provider.Name() == "2captcha" {
					t.Error("the per-request provider was added to the shared chain")
				}
			}
			next := chain.NewRequest(RequestPolicy{})
			if !enabled && next.Active() {
				t.Error("a later request without a key became active")
			}
			if shared, _ := json.Marshal(chain.GetMetrics()); bytes.Contains(shared, []byte(requestKey)) {
				t.Error("shared metrics contain the per-request key")
			}
		})
	}

	t.Run("unknown provider buys nothing", func(t *testing.T) {
		request := NewSolverChain(SolverChainConfig{}).NewRequest(RequestPolicy{Solver: "nosuch", APIKey: requestKey})
		if request.Active() {
			t.Error("Active() = true for an unregistered provider")
		}
	})
}

// TestRequestSolver_TimeoutAfterCreateStopsTheRequest: once a task was created
// and timed out, nothing more is bought — not from the next provider, and not
// on a later pass, even with budget left.
func TestRequestSolver_TimeoutAfterCreateStopsTheRequest(t *testing.T) {
	slow, next := newFakeProvider(t).onPoll(ok(processing)), newFakeProvider(t)

	slowProvider := NewTwoCaptchaSolver(TwoCaptchaConfig{
		APIKey: "server-side-value", BaseURL: slow.URL, Timeout: 40 * time.Millisecond, PollInterval: testPollInterval,
	})
	request := NewSolverChain(SolverChainConfig{
		Providers:         []CaptchaSolver{slowProvider, serverProvider(t, "anticaptcha", next.URL)},
		FallbackEnabled:   true,
		MaxExternalSolves: 3,
	}).NewRequest(RequestPolicy{})

	_, err := buyTurnstile(request, turnstileReq)
	if !errors.Is(err, types.ErrCaptchaSolverTimeout) {
		t.Fatalf("error = %v, want ErrCaptchaSolverTimeout", err)
	}
	if slow.createCount() != 1 {
		t.Errorf("slow provider createTask calls = %d, want 1", slow.createCount())
	}
	if next.createCount() != 0 {
		t.Errorf("next provider createTask calls = %d, want 0: a timeout must not cascade", next.createCount())
	}
	if request.Active() || request.ShouldFallback(100) || request.Remaining() != 0 {
		t.Error("request still wants to buy after a paid task timed out")
	}

	if _, err := buyTurnstile(request, turnstileReq); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
		t.Errorf("later pass error = %v, want ErrCaptchaBudgetExhausted", err)
	}
	if _, err := buyHCaptcha(request); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
		t.Errorf("later hCaptcha pass error = %v, want ErrCaptchaBudgetExhausted", err)
	}
	if slow.createCount() != 1 || next.createCount() != 0 {
		t.Errorf("createTask calls after later passes: slow=%d next=%d, want 1 and 0", slow.createCount(), next.createCount())
	}
}

// TestRequestSolver_RefusalMovesOnWithoutSpending: a provider that definitively
// refuses costs nothing, the next one is tried, and the refusal is remembered.
func TestRequestSolver_RefusalMovesOnWithoutSpending(t *testing.T) {
	refusals := map[string]reply{
		"bad key":            ok(`{"errorId":1,"errorCode":"ERROR_KEY_DOES_NOT_EXIST"}`),
		"zero balance":       ok(`{"errorId":10,"errorCode":"ERROR_ZERO_BALANCE"}`),
		"task not supported": ok(`{"errorId":1,"errorCode":"ERROR_TASK_NOT_SUPPORTED"}`),
	}
	for name, refusal := range refusals {
		t.Run(name, func(t *testing.T) {
			refusing, working := newFakeProvider(t).onCreate(refusal), newFakeProvider(t)
			request := NewSolverChain(SolverChainConfig{
				Providers: []CaptchaSolver{
					serverProvider(t, "2captcha", refusing.URL),
					serverProvider(t, "anticaptcha", working.URL),
				},
				FallbackEnabled:   true,
				MaxExternalSolves: 1,
			}).NewRequest(RequestPolicy{})

			result, err := buyHCaptcha(request)
			if err != nil {
				t.Fatalf("buy error = %v, want the second provider to solve it", err)
			}
			if result.Provider != "anticaptcha" {
				t.Errorf("Provider = %q, want anticaptcha", result.Provider)
			}
			if refusing.createCount() != 1 || working.createCount() != 1 {
				t.Errorf("createTask calls: refusing=%d working=%d, want 1 and 1", refusing.createCount(), working.createCount())
			}
			if request.Remaining() != 0 {
				t.Errorf("Remaining() = %d, want 0", request.Remaining())
			}
		})
	}

	t.Run("every provider refuses", func(t *testing.T) {
		first := newFakeProvider(t).onCreate(refusals["bad key"])
		second := newFakeProvider(t).onCreate(refusals["zero balance"])
		request := NewSolverChain(SolverChainConfig{
			Providers: []CaptchaSolver{
				serverProvider(t, "2captcha", first.URL),
				serverProvider(t, "anticaptcha", second.URL),
			},
			FallbackEnabled:   true,
			MaxExternalSolves: 1,
		}).NewRequest(RequestPolicy{})

		_, err := buyTurnstile(request, turnstileReq)
		if !errors.Is(err, types.ErrCaptchaSolverBalance) {
			t.Fatalf("error = %v, want the last provider's refusal", err)
		}
		if request.Remaining() != 1 {
			t.Errorf("Remaining() = %d, want 1: nothing was bought", request.Remaining())
		}
		// Nobody is left to ask about Turnstile, so the loop must stop asking.
		if request.ShouldFallback(100) {
			t.Error("ShouldFallback = true although every provider refused Turnstile")
		}
		for pass := 0; pass < 5; pass++ {
			if _, err := buyTurnstile(request, turnstileReq); err == nil {
				t.Fatal("later pass succeeded")
			}
		}
		if first.createCount() != 1 || second.createCount() != 1 {
			t.Errorf("createTask calls: first=%d second=%d, want each refused provider asked once", first.createCount(), second.createCount())
		}
	})
}

// TestRequestSolver_ManagedChallengeSkipsCapSolver: CapSolver refuses a managed
// challenge without any HTTP call and the next provider gets the parameters.
func TestRequestSolver_ManagedChallengeSkipsCapSolver(t *testing.T) {
	capSolver, twoCaptcha := newFakeProvider(t).onCreate(ok(capSolverCreated)), newFakeProvider(t)
	managed := &TurnstileRequest{
		SiteKey: "0x4AAAAAAADnPIDROrmt1Wwj", PageURL: "https://example.com",
		Action: "managed", CData: "cdata-value", PageData: "pagedata-value", UserAgent: "Mozilla/5.0 page",
	}

	t.Run("falls through to a capable provider", func(t *testing.T) {
		request := NewSolverChain(SolverChainConfig{
			Providers: []CaptchaSolver{
				serverProvider(t, "capsolver", capSolver.URL),
				serverProvider(t, "9kw", closedServerURL()),
				serverProvider(t, "2captcha", twoCaptcha.URL),
			},
			FallbackEnabled:   true,
			MaxExternalSolves: 1,
		}).NewRequest(RequestPolicy{})

		result, err := buyTurnstile(request, managed)
		if err != nil {
			t.Fatalf("buy error = %v", err)
		}
		if result.Provider != "2captcha" {
			t.Errorf("Provider = %q, want 2captcha", result.Provider)
		}
		if capSolver.createCount() != 0 || capSolver.pollCount() != 0 {
			t.Errorf("CapSolver HTTP calls = %d/%d, want none", capSolver.createCount(), capSolver.pollCount())
		}
		task := twoCaptcha.lastTask(t)
		if task["pagedata"] != "pagedata-value" || task["data"] != "cdata-value" || task["action"] != "managed" {
			t.Errorf("2captcha task = %v, want the managed-challenge parameters", task)
		}
		if task["userAgent"] != "Mozilla/5.0 page" {
			t.Errorf("task userAgent = %v, want the page's User-Agent", task["userAgent"])
		}
	})

	t.Run("capsolver alone buys nothing and stops asking", func(t *testing.T) {
		request := NewSolverChain(SolverChainConfig{
			Providers:         []CaptchaSolver{serverProvider(t, "capsolver", capSolver.URL)},
			FallbackEnabled:   true,
			MaxExternalSolves: 1,
		}).NewRequest(RequestPolicy{})

		_, err := buyTurnstile(request, managed)
		if !errors.Is(err, types.ErrCaptchaSolverRejected) {
			t.Fatalf("error = %v, want a rejection", err)
		}
		if request.ShouldFallback(100) {
			t.Error("ShouldFallback = true although the only provider cannot solve this Turnstile")
		}
		// hCaptcha is a different question and CapSolver was not asked it.
		if !request.CanSolveHCaptcha() {
			t.Error("CanSolveHCaptcha = false: a Turnstile refusal must not block hCaptcha")
		}
		if capSolver.createCount() != 0 {
			t.Errorf("CapSolver createTask calls = %d, want 0", capSolver.createCount())
		}
	})
}

// TestRequestSolver_FailureAfterCreate: a task that was created and then failed
// has spent its unit. The next provider is tried only if budget remains.
func TestRequestSolver_FailureAfterCreate(t *testing.T) {
	failures := map[string]func(f *fakeProvider){
		"unsolvable while polling": func(f *fakeProvider) {
			f.onPoll(ok(`{"errorId":1,"errorCode":"ERROR_CAPTCHA_UNSOLVABLE"}`))
		},
		"createTask answered 500": func(f *fakeProvider) {
			f.onCreate(reply{status: http.StatusInternalServerError, body: "oops"})
		},
	}
	for name, script := range failures {
		for _, budget := range []int{1, 2} {
			t.Run(name+"/budget "+string(rune('0'+budget)), func(t *testing.T) {
				failing, working := newFakeProvider(t), newFakeProvider(t)
				script(failing)
				request := NewSolverChain(SolverChainConfig{
					Providers: []CaptchaSolver{
						serverProvider(t, "2captcha", failing.URL),
						serverProvider(t, "anticaptcha", working.URL),
					},
					FallbackEnabled:   true,
					MaxExternalSolves: budget,
				}).NewRequest(RequestPolicy{})

				result, err := buyTurnstile(request, turnstileReq)
				if budget == 1 {
					if !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
						t.Fatalf("error = %v, want ErrCaptchaBudgetExhausted", err)
					}
					if working.createCount() != 0 {
						t.Errorf("second provider createTask calls = %d, want 0 with a budget of 1", working.createCount())
					}
				} else {
					if err != nil {
						t.Fatalf("buy error = %v, want the second provider to solve it", err)
					}
					if result.Provider != "anticaptcha" || working.createCount() != 1 {
						t.Errorf("Provider = %q, second provider createTask calls = %d", result.Provider, working.createCount())
					}
				}
				if failing.createCount() != 1 {
					t.Errorf("failing provider createTask calls = %d, want 1", failing.createCount())
				}
				if request.Remaining() != 0 {
					t.Errorf("Remaining() = %d, want 0", request.Remaining())
				}
			})
		}
	}
}

// TestRequestSolver_DoesNotBuyAtTheDeadline: a task created seconds before the
// request's deadline would be paid for and never collected.
func TestRequestSolver_DoesNotBuyAtTheDeadline(t *testing.T) {
	tests := []struct {
		name     string
		left     time.Duration // zero means no deadline
		wantBuys bool
	}{
		{name: "no deadline", wantBuys: true},
		{name: "plenty of time", left: time.Minute, wantBuys: true},
		{name: "just under the window", left: minExternalSolveWindow - time.Second},
		{name: "about to expire", left: 200 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t)
			request := NewSolverChain(SolverChainConfig{
				Providers:         []CaptchaSolver{serverProvider(t, "2captcha", fake.URL)},
				FallbackEnabled:   true,
				MaxExternalSolves: 1,
			}).NewRequest(RequestPolicy{})

			ctx := context.Background()
			if tt.left > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.left)
				defer cancel()
			}
			_, err := request.buy(ctx, kindTurnstile, func(p CaptchaSolver) (*TurnstileResult, error) {
				return p.SolveTurnstile(ctx, turnstileReq)
			})

			if tt.wantBuys {
				if err != nil || fake.createCount() != 1 {
					t.Fatalf("error = %v, createTask calls = %d; want a purchase", err, fake.createCount())
				}
				return
			}
			if !errors.Is(err, types.ErrCaptchaInsufficientTime) {
				t.Errorf("error = %v, want ErrCaptchaInsufficientTime", err)
			}
			if fake.createCount() != 0 {
				t.Errorf("createTask calls = %d, want 0", fake.createCount())
			}
			if request.Remaining() != 1 {
				t.Errorf("Remaining() = %d, want the budget untouched", request.Remaining())
			}
		})
	}
}

func TestRequestSolver_RecordsMetrics(t *testing.T) {
	refusing := newFakeProvider(t).onCreate(ok(`{"errorId":1,"errorCode":"ERROR_KEY_DOES_NOT_EXIST"}`))
	working := newFakeProvider(t).onPoll(ok(`{"errorId":0,"status":"ready","solution":{"token":"t"},"cost":"0.002"}`))
	metrics := NewMetrics()
	chain := NewSolverChain(SolverChainConfig{
		Providers: []CaptchaSolver{
			serverProvider(t, "2captcha", refusing.URL),
			serverProvider(t, "anticaptcha", working.URL),
		},
		Metrics:           metrics,
		FallbackEnabled:   true,
		MaxExternalSolves: 1,
	})
	if _, err := buyTurnstile(chain.NewRequest(RequestPolicy{}), turnstileReq); err != nil {
		t.Fatalf("buy error = %v", err)
	}

	stats := metrics.Snapshot()
	if got := stats["2captcha"]; got.Attempts != 1 || got.Failures != 1 || got.Tasks != 0 || got.LastError == "" {
		t.Errorf("2captcha stats = %+v, want 1 failed attempt, no task, an error", got)
	}
	if got := stats["anticaptcha"]; got.Attempts != 1 || got.Successes != 1 || got.Tasks != 1 || got.TotalCost != 0.002 {
		t.Errorf("anticaptcha stats = %+v, want 1 success, 1 task, cost 0.002", got)
	}
	if chain.GetMetrics() == nil {
		t.Error("GetMetrics() = nil")
	}
}

func TestWarnOnAgentMismatch(t *testing.T) {
	tests := []struct {
		name      string
		provider  string
		page      string
		wantWarns bool
	}{
		{"different agents", "Mozilla/5.0 worker Chrome/120", "Mozilla/5.0 page Chrome/140", true},
		{"same agent", "Mozilla/5.0 same", "Mozilla/5.0 same", false},
		{"provider reported none", "", "Mozilla/5.0 page", false},
		{"page agent unknown", "Mozilla/5.0 worker", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			warnOnAgentMismatch(&TurnstileResult{Provider: "2captcha", UserAgent: tt.provider}, tt.page)
			warned := strings.Contains(logs.String(), "different User-Agent")
			if warned != tt.wantWarns {
				t.Errorf("warned = %v, want %v (log: %s)", warned, tt.wantWarns, logs.String())
			}
		})
	}
}

// nineKwFake is a minimal 9kw endpoint: it records the apikey it was sent and
// answers from fixed bodies.
type nineKwFake struct {
	*httptest.Server
	mu      sync.Mutex
	keys    []string
	uploads int
}

func newNineKwFake(t *testing.T, upload, result string) *nineKwFake {
	t.Helper()
	f := &nineKwFake{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.keys = append(f.keys, q.Get("apikey"))
		if q.Get("action") == nineKwActionUpload {
			f.uploads++
		}
		f.mu.Unlock()
		if q.Get("action") == nineKwActionUpload {
			_, _ = w.Write([]byte(upload))
			return
		}
		_, _ = w.Write([]byte(result))
	}))
	t.Cleanup(f.Close)
	return f
}

// TestRequestSolver_PerRequestKeyNeverLeaks drives every provider through the
// ways a solve can go wrong (and right) with a per-request key, capturing all
// log output at trace level, and then greps the logs, the returned error and
// the shared metrics for the key.
func TestRequestSolver_PerRequestKeyNeverLeaks(t *testing.T) {
	const requestKey = "leak-probe-value-7f3a9c21d4"
	echo := `"errorDescription":"clientKey ` + requestKey + ` is not authorized"`

	type scenario struct {
		name string
		// baseURL returns the provider base URL for this scenario.
		baseURL func(t *testing.T, provider string) string
		wantErr bool
	}
	createTaskScenarios := []scenario{
		{name: "success", baseURL: func(t *testing.T, provider string) string {
			f := newFakeProvider(t)
			if provider == "capsolver" {
				f.onCreate(ok(capSolverCreated))
			}
			f.onPoll(ok(`{"errorId":0,"status":"ready","solution":{"token":"t","userAgent":"Mozilla/5.0 other"}}`))
			return f.URL
		}},
		{name: "provider echoes the key at createTask", wantErr: true, baseURL: func(t *testing.T, _ string) string {
			return newFakeProvider(t).onCreate(ok(`{"errorId":1,"errorCode":"ERROR_ODD",` + echo + `}`)).URL
		}},
		{name: "provider echoes the key while polling", wantErr: true, baseURL: func(t *testing.T, provider string) string {
			f := newFakeProvider(t).onPoll(ok(`{"errorId":1,"errorCode":"ERROR_ODD",` + echo + `}`))
			if provider == "capsolver" {
				f.onCreate(ok(capSolverCreated))
			}
			return f.URL
		}},
		{name: "known error code", wantErr: true, baseURL: func(t *testing.T, _ string) string {
			return newFakeProvider(t).onCreate(ok(`{"errorId":1,"errorCode":"ERROR_KEY_DOES_NOT_EXIST",` + echo + `}`)).URL
		}},
		{name: "http 500 echoing the key", wantErr: true, baseURL: func(t *testing.T, _ string) string {
			return newFakeProvider(t).onCreate(reply{status: http.StatusInternalServerError, body: "bad key " + requestKey}).URL
		}},
		{name: "html echoing the key", wantErr: true, baseURL: func(t *testing.T, _ string) string {
			return newFakeProvider(t).onCreate(ok("<html>" + requestKey + "</html>")).URL
		}},
		{name: "flaky polls then give up", wantErr: true, baseURL: func(t *testing.T, provider string) string {
			f := newFakeProvider(t).onPoll(reply{status: http.StatusBadGateway, body: requestKey})
			if provider == "capsolver" {
				f.onCreate(ok(capSolverCreated))
			}
			return f.URL
		}},
		{name: "connection refused", wantErr: true, baseURL: func(*testing.T, string) string { return closedServerURL() }},
	}

	check := func(t *testing.T, logs *syncBuffer, err error, chain *SolverChain) {
		t.Helper()
		if strings.Contains(logs.String(), requestKey) {
			t.Errorf("log output contains the per-request key:\n%s", logs.String())
		}
		if err != nil && strings.Contains(err.Error(), requestKey) {
			t.Errorf("error text contains the per-request key: %v", err)
		}
		for unwrapped := err; unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
			var captchaErr *types.CaptchaError
			if errors.As(unwrapped, &captchaErr) && strings.Contains(captchaErr.Message+captchaErr.Code+captchaErr.TaskID, requestKey) {
				t.Errorf("CaptchaError carries the per-request key: %+v", captchaErr)
			}
		}
		if shared, _ := json.Marshal(chain.GetMetrics()); bytes.Contains(shared, []byte(requestKey)) {
			t.Errorf("shared metrics contain the per-request key: %s", shared)
		}
		if logs.String() == "" {
			t.Error("nothing was logged: the capture is not working")
		}
	}

	for _, provider := range []string{"2captcha", "anticaptcha", "capsolver"} {
		for _, sc := range createTaskScenarios {
			t.Run(provider+"/"+sc.name, func(t *testing.T) {
				logs := captureLogs(t)
				chain := NewSolverChain(SolverChainConfig{
					Metrics:         NewMetrics(),
					ProviderTimeout: testTimeout,
					PollInterval:    testPollInterval,
					BaseURLs:        map[string]string{provider: sc.baseURL(t, provider)},
				})
				request := chain.NewRequest(RequestPolicy{Solver: provider, APIKey: requestKey})

				result, err := buyTurnstile(request, turnstileReq)
				if (err != nil) != sc.wantErr {
					t.Fatalf("buy error = %v, wantErr %v", err, sc.wantErr)
				}
				if result != nil {
					warnOnAgentMismatch(result, "Mozilla/5.0 page")
				}
				check(t, logs, err, chain)
			})
		}
	}

	// 9kw carries the key in the query string of a GET, and only solves hCaptcha.
	nineKwScenarios := []struct {
		name    string
		upload  string
		result  string
		closed  bool
		wantErr bool
	}{
		{name: "success", upload: `{"captchaid":130875948}`, result: `{"answer":"P1_token","try_again":0}`},
		{name: "upload error echoing the key", upload: `{"error":"0099 key ` + requestKey + ` rejected"}`, wantErr: true},
		{name: "known upload error", upload: `{"error":"0003 Active API key not found"}`, wantErr: true},
		{name: "result error echoing the key", upload: `{"captchaid":"7"}`, result: `{"error":"0099 ` + requestKey + `"}`, wantErr: true},
		{name: "html echoing the key", upload: "<html>" + requestKey + "</html>", wantErr: true},
		{name: "connection refused", closed: true, wantErr: true},
	}
	for _, sc := range nineKwScenarios {
		t.Run("9kw/"+sc.name, func(t *testing.T) {
			logs := captureLogs(t)
			baseURL := closedServerURL()
			var fake *nineKwFake
			if !sc.closed {
				fake = newNineKwFake(t, sc.upload, sc.result)
				baseURL = fake.URL
			}
			chain := NewSolverChain(SolverChainConfig{
				Metrics:         NewMetrics(),
				ProviderTimeout: testTimeout,
				PollInterval:    testPollInterval,
				BaseURLs:        map[string]string{"9kw": baseURL},
			})
			request := chain.NewRequest(RequestPolicy{Solver: "9kw", APIKey: requestKey})

			_, err := buyHCaptcha(request)
			if (err != nil) != sc.wantErr {
				t.Fatalf("buy error = %v, wantErr %v", err, sc.wantErr)
			}
			if fake != nil {
				fake.mu.Lock()
				if len(fake.keys) == 0 || fake.keys[0] != requestKey {
					t.Errorf("9kw received apikey %v, want the request's key", fake.keys)
				}
				if fake.uploads != 1 {
					t.Errorf("9kw uploads = %d, want 1", fake.uploads)
				}
				fake.mu.Unlock()
			}
			check(t, logs, err, chain)

			// 9kw refuses Turnstile without a request, whatever the key.
			if _, err := buyTurnstile(chain.NewRequest(RequestPolicy{Solver: "9kw", APIKey: requestKey}), turnstileReq); err == nil || TaskCreated(err) {
				t.Errorf("9kw Turnstile: err = %v, want a not-created refusal", err)
			}
			check(t, logs, err, chain)
		})
	}
}

package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/captcha"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// keyRecorder is a fake createTask-style provider that records the clientKey of
// every request it receives.
type keyRecorder struct {
	*httptest.Server
	mu   sync.Mutex
	keys []string
}

func newKeyRecorder(t *testing.T) *keyRecorder {
	t.Helper()
	r := &keyRecorder{}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		var decoded struct {
			ClientKey string `json:"clientKey"`
		}
		_ = json.Unmarshal(body, &decoded)
		r.mu.Lock()
		r.keys = append(r.keys, decoded.ClientKey)
		r.mu.Unlock()
		_, _ = w.Write([]byte(`{"errorId":0,"balance":1.5}`))
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *keyRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...)
}

func providerNames(chain *captcha.SolverChain) []string {
	var names []string
	for _, provider := range chain.GetProviders() {
		names = append(names, provider.Name())
	}
	return names
}

// TestNewCaptchaChain covers how configuration becomes the solver chain: off by
// default, ordered by the primary provider, budget and base URLs passed on.
func TestNewCaptchaChain(t *testing.T) {
	tests := []struct {
		name          string
		cfg           config.Config
		wantEnabled   bool
		wantProviders []string
		wantBudget    int
	}{
		{
			name:       "nothing configured",
			cfg:        config.Config{CaptchaMaxExternalSolves: 1},
			wantBudget: 1,
		},
		{
			name: "keys present but the fallback is not enabled",
			cfg: config.Config{
				Captcha2CaptchaAPIKey:    "configured-value-1",
				CaptchaCapSolverAPIKey:   "configured-value-2",
				CaptchaMaxExternalSolves: 3,
			},
			wantBudget: 3,
		},
		{
			name:       "fallback enabled without keys",
			cfg:        config.Config{CaptchaFallbackEnabled: true, CaptchaMaxExternalSolves: 1},
			wantBudget: 1,
		},
		{
			name: "fallback enabled, primary first, rest sorted",
			cfg: config.Config{
				CaptchaFallbackEnabled:   true,
				CaptchaPrimaryProvider:   "capsolver",
				Captcha2CaptchaAPIKey:    "configured-value-1",
				CaptchaCapSolverAPIKey:   "configured-value-2",
				CaptchaAntiCaptchaAPIKey: "configured-value-3",
				Captcha9kwAPIKey:         "configured-value-4",
				CaptchaMaxExternalSolves: 2,
			},
			wantEnabled:   true,
			wantProviders: []string{"capsolver", "2captcha", "9kw", "anticaptcha"},
			wantBudget:    2,
		},
		{
			name: "only providers with a key are built",
			cfg: config.Config{
				CaptchaFallbackEnabled:   true,
				CaptchaPrimaryProvider:   "2captcha",
				CaptchaAntiCaptchaAPIKey: "configured-value-3",
				CaptchaMaxExternalSolves: 1,
			},
			wantEnabled:   true,
			wantProviders: []string{"anticaptcha"},
			wantBudget:    1,
		},
		{
			name: "budget of zero keeps the chain from buying",
			cfg: config.Config{
				CaptchaFallbackEnabled:   true,
				Captcha2CaptchaAPIKey:    "configured-value-1",
				CaptchaMaxExternalSolves: 0,
			},
			wantEnabled:   true,
			wantProviders: []string{"2captcha"},
			wantBudget:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.CaptchaNativeAttempts = 4
			cfg.CaptchaSolverTimeout = 30 * time.Second
			chain := newCaptchaChain(&cfg)

			if chain == nil {
				t.Fatal("newCaptchaChain returned nil: a request with its own key could not be served")
			}
			if chain.IsEnabled() != tt.wantEnabled {
				t.Errorf("IsEnabled() = %v, want %v", chain.IsEnabled(), tt.wantEnabled)
			}
			if got := strings.Join(providerNames(chain), ","); got != strings.Join(tt.wantProviders, ",") {
				t.Errorf("providers = %q, want %q", got, strings.Join(tt.wantProviders, ","))
			}
			if chain.MaxExternalSolves() != tt.wantBudget {
				t.Errorf("MaxExternalSolves() = %d, want %d", chain.MaxExternalSolves(), tt.wantBudget)
			}
			if chain.NativeAttempts() != 4 {
				t.Errorf("NativeAttempts() = %d, want 4", chain.NativeAttempts())
			}
			if chain.Metrics() == nil {
				t.Error("the chain was built without a metrics tracker")
			}

			// What an ordinary request may buy follows from all of the above.
			wantActive := tt.wantEnabled && tt.wantBudget > 0
			if got := chain.NewRequest(captcha.RequestPolicy{}).Active(); got != wantActive {
				t.Errorf("an ordinary request is active = %v, want %v", got, wantActive)
			}
			// A request with its own key is always served, with one task.
			own := chain.NewRequest(captcha.RequestPolicy{Solver: "capsolver", APIKey: "request-scoped-value"})
			if !own.Active() || own.Remaining() != 1 {
				t.Errorf("a request with its own key: Active() = %v, Remaining() = %d; want true and 1", own.Active(), own.Remaining())
			}
			// And "none" always wins.
			if chain.NewRequest(captcha.RequestPolicy{Solver: "none"}).Active() {
				t.Error("captchaSolver none left the request able to buy")
			}
		})
	}
}

// TestNewCaptchaChain_BaseURLOverrides: each provider's override reaches the
// provider built from the server's key.
func TestNewCaptchaChain_BaseURLOverrides(t *testing.T) {
	twoCaptcha, capSolver, antiCaptcha := newKeyRecorder(t), newKeyRecorder(t), newKeyRecorder(t)
	cfg := &config.Config{
		CaptchaFallbackEnabled:    true,
		CaptchaPrimaryProvider:    "2captcha",
		Captcha2CaptchaAPIKey:     "configured-value-1",
		CaptchaCapSolverAPIKey:    "configured-value-2",
		CaptchaAntiCaptchaAPIKey:  "configured-value-3",
		Captcha2CaptchaBaseURL:    twoCaptcha.URL,
		CaptchaCapSolverBaseURL:   capSolver.URL,
		CaptchaAntiCaptchaBaseURL: antiCaptcha.URL,
		CaptchaMaxExternalSolves:  1,
		CaptchaSolverTimeout:      30 * time.Second,
	}
	chain := newCaptchaChain(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, provider := range chain.GetProviders() {
		if _, err := provider.Balance(ctx); err != nil {
			t.Fatalf("%s Balance() error = %v", provider.Name(), err)
		}
	}

	for name, want := range map[string]struct {
		recorder *keyRecorder
		key      string
	}{
		"2captcha":    {twoCaptcha, "configured-value-1"},
		"capsolver":   {capSolver, "configured-value-2"},
		"anticaptcha": {antiCaptcha, "configured-value-3"},
	} {
		seen := want.recorder.seen()
		if len(seen) != 1 || seen[0] != want.key {
			t.Errorf("%s override received keys %v, want exactly [%s]", name, seen, want.key)
		}
	}
}

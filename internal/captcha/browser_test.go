package captcha_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/captcha"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	turnstileKey = "0x4AAAAAAADnPIDROrmt1Wwj"
	hcaptchaKey  = "10000000-ffff-ffff-ffff-000000000001"

	// hostileToken is what a solved token must survive unchanged: quotes, a
	// backslash, a newline, a script terminator and an injection attempt.
	hostileToken = `tok'"\` + "\n" + `</script>');window.pwned=1;//`

	browserTestTimeout = 60 * time.Second
)

// fixtures are the pages the browser tests load, by path.
var fixtures = map[string]string{
	"/empty": `<html><body><p>nothing here</p></body></html>`,

	// Things the old injection code counted as success without delivering anything.
	"/turnstile-global-only": `<html><body><script>window.turnstile = {};</script></body></html>`,
	"/recaptcha-field-only":  `<html><body><form><input name="g-recaptcha-response"></form></body></html>`,
	"/hcaptcha-field-only":   `<html><body><form><textarea name="h-captcha-response"></textarea></form></body></html>`,
	"/hcaptcha-global-only":  `<html><body><script>window.hcaptcha = { getRespKey: function() {} };</script></body></html>`,

	"/turnstile-field": `<html><body><form>
		<div class="cf-turnstile" data-sitekey="` + turnstileKey + `">
			<input type="hidden" name="cf-turnstile-response">
			<input type="hidden" name="g-recaptcha-response">
		</div>
		<textarea name="h-captcha-response"></textarea>
	</form></body></html>`,

	"/turnstile-callback": `<html><body>
		<script>window.calls = []; function onDone(token) { window.calls.push(token); }</script>
		<div class="cf-turnstile" data-sitekey="` + turnstileKey + `" data-callback="onDone"></div>
		<div class="cf-turnstile" data-sitekey="` + turnstileKey + `" data-callback="onDone"></div>
	</body></html>`,

	"/turnstile-callback-throws": `<html><body>
		<script>function onDone(token) { throw new Error('nope'); }</script>
		<div class="cf-turnstile" data-sitekey="` + turnstileKey + `" data-callback="onDone"></div>
	</body></html>`,

	"/turnstile-window-callback": `<html><body>
		<script>window.calls = []; window.turnstileCallback = function(token) { window.calls.push(token); };</script>
	</body></html>`,

	"/hcaptcha-widget": `<html><body><form>
		<script>window.calls = []; function onHC(token) { window.calls.push(token); }</script>
		<div class="h-captcha" data-sitekey="` + hcaptchaKey + `" data-callback="onHC" data-action="hc-action">
			<textarea name="h-captcha-response"></textarea>
			<textarea name="g-recaptcha-response"></textarea>
		</div>
	</form></body></html>`,

	// The Turnstile widget sits after an unrelated element carrying data-action
	// and data-cdata, which the old extraction picked up instead.
	"/scoping": `<html><body>
		<button data-action="add-to-cart" data-cdata="tracking-blob">Buy</button>
		<div class="h-captcha" data-sitekey="` + hcaptchaKey + `" data-action="hc-action"></div>
		<div class="cf-turnstile" data-sitekey="` + turnstileKey + `" data-action="login" data-cdata="session-42"></div>
	</body></html>`,

	"/scoping-no-action": `<html><body>
		<button data-action="add-to-cart" data-cdata="tracking-blob">Buy</button>
		<div class="cf-turnstile" data-sitekey="` + turnstileKey + `"></div>
	</body></html>`,

	// Nothing here is a Turnstile widget, though the word and a sitekey appear.
	"/lookalikes": `<html><body>
		<a href="https://example.com/turnstile?sitekey=` + turnstileKey + `">docs</a>
		<iframe src="/empty?turnstile=1&sitekey=` + turnstileKey + `"></iframe>
		<div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"></div>
		<div class="h-captcha" data-sitekey="` + hcaptchaKey + `"></div>
		<script>var config = { sitekey: "` + hcaptchaKey + `" }; hcaptcha_like({ sitekey: '` + turnstileKey + `' });</script>
	</body></html>`,

	"/script-render": `<html><body><div id="w"></div>
		<script>function boot() { turnstile.render('#w', { sitekey: '` + turnstileKey + `' }); }</script>
	</body></html>`,

	// A widget rendered by script, as on a managed challenge: the parameters
	// exist only as arguments to turnstile.render(). The DOM carries decoys.
	"/managed": `<html><body>
		<div data-action="decoy-action" data-cdata="decoy-cdata" data-sitekey="` + hcaptchaKey + `"></div>
		<div class="cf-turnstile" data-sitekey="0x4BBBBBBBBnPIDROrmt1Wwj" data-action="dom-action" data-cdata="dom-cdata"></div>
		<div id="w"></div>
		<script>
			window.calls = [];
			window.turnstile = { render: function(container, params) { window.rendered = true; return 'widget-1'; } };
			turnstile.render('#w', {
				sitekey: '` + turnstileKey + `',
				cData: 'managed-cdata',
				chlPageData: 'managed-pagedata',
				callback: function(token) { window.calls.push(token); }
			});
		</script>
	</body></html>`,

	// The child frame of the OOPIF fixture: it renders the widget and reports
	// the token it is given back to its parent.
	"/oopif-child": `<html><body><div id="w"></div>
		<script>
			window.turnstile = { render: function() { return 'widget-1'; } };
			turnstile.render('#w', {
				sitekey: '` + turnstileKey + `',
				action: 'managed',
				cData: 'oopif-cdata',
				chlPageData: 'oopif-pagedata',
				callback: function(token) { parent.postMessage({ token: token }, '*'); }
			});
			parent.postMessage({ ready: true }, '*');
		</script>
	</body></html>`,
}

// site serves the fixtures and plays the captcha provider.
type site struct {
	*httptest.Server

	mu      sync.Mutex
	creates []map[string]any
	token   string
}

func newSite(t *testing.T) *site {
	t.Helper()
	s := &site{token: hostileToken}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *site) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/createTask":
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		s.mu.Lock()
		s.creates = append(s.creates, decoded)
		s.mu.Unlock()
		_, _ = w.Write([]byte(`{"errorId":0,"taskId":4242}`))
	case "/getTaskResult":
		s.mu.Lock()
		token := s.token
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errorId":  0,
			"status":   "ready",
			"solution": map[string]string{"token": token, "userAgent": "Mozilla/5.0 (provider worker)"},
			"cost":     "0.00145",
		})
	case "/oopif-parent":
		// The child is loaded from another site (localhost vs 127.0.0.1) and
		// declares Document-Isolation-Policy, which is what forces it into its
		// own process — a real out-of-process iframe — in the pool's browser,
		// where go-rod's launcher has site isolation trials switched off. This
		// mirrors how Cloudflare's challenge iframe isolates itself. The parent
		// is cross-origin isolated (COOP + COEP) so the child may be embedded.
		child := strings.Replace(s.URL, "127.0.0.1", "localhost", 1) + "/oopif-child"
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>
			window.messages = [];
			window.addEventListener('message', function(e) { window.messages.push(e.data); });
		</script><iframe src="` + child + `"></iframe></body></html>`))
	default:
		page, found := fixtures[r.URL.Path]
		if !found {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/oopif-child" {
			w.Header().Set("Document-Isolation-Policy", "isolate-and-require-corp")
			w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page))
	}
}

func (s *site) createCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.creates)
}

func (s *site) lastTask(t *testing.T) map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.creates) == 0 {
		t.Fatal("the provider received no createTask")
	}
	task, _ := s.creates[len(s.creates)-1]["task"].(map[string]any)
	return task
}

// chain returns a solver chain whose 2captcha provider is this site.
func (s *site) chain(maxSolves int) *captcha.SolverChain {
	provider := captcha.NewTwoCaptchaSolver(captcha.TwoCaptchaConfig{
		APIKey:       "server-side-value",
		BaseURL:      s.URL,
		Timeout:      10 * time.Second,
		PollInterval: 5 * time.Millisecond,
	})
	return captcha.NewSolverChain(captcha.SolverChainConfig{
		Providers:         []captcha.CaptchaSolver{provider},
		Metrics:           captcha.NewMetrics(),
		FallbackEnabled:   true,
		MaxExternalSolves: maxSolves,
	})
}

// startBrowser launches one real browser for the whole test.
func startBrowser(t *testing.T) *rod.Browser {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping browser test in short mode")
	}
	pool, err := browser.NewPool(&config.Config{
		Headless:           true,
		BrowserPoolSize:    1,
		BrowserPoolTimeout: 30 * time.Second,
		MaxMemoryMB:        1024,
	})
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), browserTestTimeout)
	defer cancel()
	br, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	t.Cleanup(func() { pool.Release(br) })
	return br
}

// startIsolatedBrowser launches a browser with strict site isolation, so that a
// cross-site iframe becomes a separate process and target. The pool's browsers
// inherit go-rod's --disable-site-isolation-trials and only get an OOPIF from a
// frame that isolates itself with headers, as Cloudflare's challenge frame
// does; not every Chromium build honors those headers, but all honor this.
func startIsolatedBrowser(t *testing.T) *rod.Browser {
	t.Helper()
	l := launcher.New().
		Headless(true).
		Delete("disable-site-isolation-trials").
		Set("disable-features", "TranslateUI").
		Set("site-per-process")
	controlURL, err := l.Launch()
	if err != nil {
		t.Fatalf("Failed to launch isolated browser: %v", err)
	}
	t.Cleanup(l.Cleanup)

	br := rod.New().ControlURL(controlURL)
	if err := br.Connect(); err != nil {
		t.Fatalf("Failed to connect to isolated browser: %v", err)
	}
	t.Cleanup(func() {
		// Ignore error: cleanup should not fail the test.
		_ = br.Close()
	})
	return br
}

// blankPage opens an empty page that is closed when the test ends.
func blankPage(t *testing.T, br *rod.Browser) *rod.Page {
	t.Helper()
	page, err := br.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	t.Cleanup(func() {
		// Ignore error: the browser may already be gone at cleanup.
		_ = page.Close()
	})
	return page
}

func navigate(ctx context.Context, t *testing.T, page *rod.Page, url string) {
	t.Helper()
	if err := page.Context(ctx).Navigate(url); err != nil {
		t.Fatalf("Navigate(%s): %v", url, err)
	}
	if err := page.Context(ctx).WaitLoad(); err != nil {
		t.Fatalf("WaitLoad(%s): %v", url, err)
	}
}

// evalJSON evaluates an expression in the page and decodes its JSON value.
func evalJSON[T any](ctx context.Context, t *testing.T, page *rod.Page, expr string) T {
	t.Helper()
	var out T
	res, err := proto.RuntimeEvaluate{
		Expression:    "JSON.stringify(" + expr + ")",
		ReturnByValue: true,
	}.Call(page.Context(ctx))
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	raw := res.Result.Value.Str()
	if raw == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("eval %q returned %q: %v", expr, raw, err)
	}
	return out
}

func TestBrowser(t *testing.T) {
	br := startBrowser(t)
	web := newSite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*browserTestTimeout)
	defer cancel()

	t.Run("injection reports the truth", func(t *testing.T) {
		tests := []struct {
			name     string
			path     string
			hcaptcha bool
			wantOK   bool
			// check runs after a successful injection.
			check string // JS expression that must be true
		}{
			{name: "empty page", path: "/empty"},
			{name: "window.turnstile alone is not a delivery", path: "/turnstile-global-only"},
			{name: "a recaptcha field is not a turnstile field", path: "/recaptcha-field-only"},
			{name: "an hcaptcha field is not a turnstile field", path: "/hcaptcha-field-only"},
			{name: "callback that throws is not a delivery", path: "/turnstile-callback-throws"},
			{
				name: "turnstile field is filled, foreign field is not", path: "/turnstile-field", wantOK: true,
				check: `document.querySelector('[name="cf-turnstile-response"]').value === TOKEN &&
					document.querySelector('.cf-turnstile [name="g-recaptcha-response"]').value === TOKEN &&
					document.querySelector('[name="h-captcha-response"]').value === ''`,
			},
			{
				name: "widget callback fires once per callback", path: "/turnstile-callback", wantOK: true,
				check: `window.calls.length === 1 && window.calls[0] === TOKEN`,
			},
			{
				name: "conventional global callback", path: "/turnstile-window-callback", wantOK: true,
				check: `window.calls.length === 1 && window.calls[0] === TOKEN`,
			},
			{name: "hcaptcha: empty page", path: "/empty", hcaptcha: true},
			{name: "hcaptcha: window.hcaptcha alone is not a delivery", path: "/hcaptcha-global-only", hcaptcha: true},
			{name: "hcaptcha: a turnstile field is not an hcaptcha field", path: "/recaptcha-field-only", hcaptcha: true},
			{
				name: "hcaptcha: field filled and callback fired", path: "/hcaptcha-widget", hcaptcha: true, wantOK: true,
				check: `document.querySelector('[name="h-captcha-response"]').value === TOKEN &&
					document.querySelector('[name="g-recaptcha-response"]').value === TOKEN &&
					window.calls.length === 1 && window.calls[0] === TOKEN`,
			},
			{
				name: "hcaptcha: field alone", path: "/hcaptcha-field-only", hcaptcha: true, wantOK: true,
				check: `document.querySelector('[name="h-captcha-response"]').value === TOKEN`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				page := blankPage(t, br)
				navigate(ctx, t, page, web.URL+tt.path)

				var err error
				if tt.hcaptcha {
					err = captcha.InjectHCaptchaToken(ctx, page, hostileToken)
				} else {
					err = captcha.InjectTurnstileToken(ctx, page, hostileToken)
				}

				if !tt.wantOK {
					if !errors.Is(err, types.ErrCaptchaTokenInjection) {
						t.Fatalf("error = %v, want ErrCaptchaTokenInjection", err)
					}
				} else if err != nil {
					t.Fatalf("injection error = %v", err)
				}

				// The token is data, never code, whatever it contains.
				if evalJSON[bool](ctx, t, page, `typeof window.pwned !== 'undefined'`) {
					t.Fatal("the token was executed as JavaScript")
				}
				if tt.check != "" {
					tokenJSON, _ := json.Marshal(hostileToken)
					expr := "(function(TOKEN) { return " + tt.check + "; })(" + string(tokenJSON) + ")"
					if !evalJSON[bool](ctx, t, page, expr) {
						t.Errorf("page state after injection is wrong: %s", tt.check)
					}
				}
			})
		}
	})

	t.Run("extraction is scoped to the widget", func(t *testing.T) {
		tests := []struct {
			name      string
			path      string
			prepare   string // JS run before extraction
			want      *captcha.TurnstileWidget
			wantHCKey string
		}{
			{
				name:      "action and cdata come from the turnstile element",
				path:      "/scoping",
				want:      &captcha.TurnstileWidget{SiteKey: turnstileKey, Action: "login", CData: "session-42"},
				wantHCKey: hcaptchaKey,
			},
			{
				name: "no action is better than someone else's",
				path: "/scoping-no-action",
				want: &captcha.TurnstileWidget{SiteKey: turnstileKey},
			},
			{name: "lookalikes are not a turnstile widget", path: "/lookalikes", wantHCKey: hcaptchaKey},
			{name: "hcaptcha widget is not a turnstile widget", path: "/hcaptcha-widget", wantHCKey: hcaptchaKey},
			{name: "empty page", path: "/empty"},
			{
				name: "literal turnstile.render sitekey as a last resort",
				path: "/script-render",
				want: &captcha.TurnstileWidget{SiteKey: turnstileKey},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				page := blankPage(t, br)
				navigate(ctx, t, page, web.URL+tt.path)

				widget, err := captcha.ExtractTurnstileWidget(ctx, page)
				switch {
				case tt.want == nil && !errors.Is(err, types.ErrCaptchaSitekeyNotFound):
					t.Errorf("ExtractTurnstileWidget = %+v, %v; want ErrCaptchaSitekeyNotFound", widget, err)
				case tt.want != nil && err != nil:
					t.Errorf("ExtractTurnstileWidget error = %v", err)
				case tt.want != nil && *widget != *tt.want:
					t.Errorf("ExtractTurnstileWidget = %+v, want %+v", *widget, *tt.want)
				}

				key, err := captcha.ExtractHCaptchaSitekey(ctx, page)
				if tt.wantHCKey == "" {
					if !errors.Is(err, types.ErrCaptchaSitekeyNotFound) {
						t.Errorf("ExtractHCaptchaSitekey = %q, %v; want ErrCaptchaSitekeyNotFound", key, err)
					}
				} else if key != tt.wantHCKey {
					t.Errorf("ExtractHCaptchaSitekey = %q, %v; want %q", key, err, tt.wantHCKey)
				}
			})
		}
	})

	t.Run("extraction honors a canceled context", func(t *testing.T) {
		page := blankPage(t, br)
		navigate(ctx, t, page, web.URL+"/scoping")
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := captcha.ExtractTurnstileWidget(canceled, page); err == nil {
			t.Error("ExtractTurnstileWidget succeeded on a canceled context")
		}
		if err := captcha.InjectTurnstileToken(canceled, page, "t"); err == nil {
			t.Error("InjectTurnstileToken succeeded on a canceled context")
		}
	})

	// The whole external path against a managed-style page: intercepted
	// parameters reach the provider untouched by DOM decoys, the provider is
	// told the request's User-Agent, the token is delivered through the
	// captured callback, and the request buys exactly once.
	t.Run("managed challenge end to end with a budget of one", func(t *testing.T) {
		const pageAgent = "Mozilla/5.0 (request override) Chrome/140"
		before := web.createCount()
		chain := web.chain(1)
		request := chain.NewRequest(captcha.RequestPolicy{})

		page := blankPage(t, br)
		captcha.InstallTurnstileInterceptor(ctx, page)
		defer captcha.RemoveTurnstileInterceptor(page)
		navigate(ctx, t, page, web.URL+"/managed")

		params, captured := captcha.ReadCapturedChallengeParams(ctx, page)
		if !captured {
			t.Fatal("the render() interceptor captured nothing")
		}
		if params.SiteKey != turnstileKey || params.PageData != "managed-pagedata" {
			t.Fatalf("captured params = %+v", params)
		}
		if !request.ShouldFallback(request.NativeAttempts()) {
			t.Fatal("ShouldFallback = false before anything was bought")
		}

		result, err := request.SolveTurnstile(ctx, page, web.URL+"/managed", pageAgent)
		if err != nil {
			t.Fatalf("SolveTurnstile error = %v", err)
		}
		if !result.Injected || result.Provider != "2captcha" || result.Token != hostileToken {
			t.Errorf("result = %+v", result)
		}

		task := web.lastTask(t)
		want := map[string]any{
			"websiteKey": turnstileKey,
			"data":       "managed-cdata",
			"pagedata":   "managed-pagedata",
			"userAgent":  pageAgent,
			"websiteURL": web.URL + "/managed",
		}
		for key, value := range want {
			if task[key] != value {
				t.Errorf("provider task[%q] = %v, want %v", key, task[key], value)
			}
		}
		// The page passed no action to render(); the DOM's must not be borrowed.
		if action, present := task["action"]; present {
			t.Errorf("provider task carries action %v scraped from the DOM", action)
		}

		calls := evalJSON[[]string](ctx, t, page, `window.calls`)
		if len(calls) != 1 || calls[0] != hostileToken {
			t.Errorf("captured callback calls = %q, want exactly the token", calls)
		}
		if evalJSON[bool](ctx, t, page, `typeof window.pwned !== 'undefined'`) {
			t.Fatal("the token was executed as JavaScript")
		}

		// The challenge is still there on the next loop passes: nothing more is bought.
		for pass := 0; pass < 5; pass++ {
			if request.ShouldFallback(request.NativeAttempts() + pass) {
				t.Fatal("ShouldFallback = true after the budget was spent")
			}
			if _, err := request.SolveTurnstile(ctx, page, web.URL+"/managed", pageAgent); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
				t.Fatalf("pass %d: error = %v, want ErrCaptchaBudgetExhausted", pass, err)
			}
			if _, err := request.SolveHCaptcha(ctx, page, web.URL+"/managed", pageAgent); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
				t.Fatalf("pass %d hCaptcha: error = %v, want ErrCaptchaBudgetExhausted", pass, err)
			}
		}
		if got := web.createCount() - before; got != 1 {
			t.Errorf("createTask calls for this request = %d, want 1", got)
		}
		if stats := chain.Metrics().Snapshot()["2captcha"]; stats.Tasks != 1 || stats.Successes != 1 {
			t.Errorf("metrics = %+v, want 1 task and 1 success", stats)
		}
	})

	t.Run("hcaptcha goes through the chain and is escaped", func(t *testing.T) {
		before := web.createCount()
		request := web.chain(1).NewRequest(captcha.RequestPolicy{})

		page := blankPage(t, br)
		navigate(ctx, t, page, web.URL+"/hcaptcha-widget")

		result, err := request.SolveHCaptcha(ctx, page, web.URL+"/hcaptcha-widget", "Mozilla/5.0 page")
		if err != nil {
			t.Fatalf("SolveHCaptcha error = %v", err)
		}
		if !result.Injected || result.Token != hostileToken {
			t.Errorf("result = %+v", result)
		}
		task := web.lastTask(t)
		if task["type"] != "HCaptchaTaskProxyless" || task["websiteKey"] != hcaptchaKey {
			t.Errorf("provider task = %v", task)
		}
		if got := evalJSON[string](ctx, t, page, `document.querySelector('[name="h-captcha-response"]').value`); got != hostileToken {
			t.Errorf("h-captcha-response = %q, want the token unchanged", got)
		}
		if evalJSON[bool](ctx, t, page, `typeof window.pwned !== 'undefined'`) {
			t.Fatal("the hCaptcha token was executed as JavaScript")
		}
		// Turnstile draws on the same budget.
		if _, err := request.SolveTurnstile(ctx, page, web.URL, "ua"); !errors.Is(err, types.ErrCaptchaBudgetExhausted) {
			t.Errorf("SolveTurnstile after hCaptcha: error = %v, want ErrCaptchaBudgetExhausted", err)
		}
		if got := web.createCount() - before; got != 1 {
			t.Errorf("createTask calls = %d, want 1", got)
		}
	})

	t.Run("nothing on the page means nothing is bought", func(t *testing.T) {
		before := web.createCount()
		request := web.chain(3).NewRequest(captcha.RequestPolicy{})

		page := blankPage(t, br)
		navigate(ctx, t, page, web.URL+"/lookalikes")

		if _, err := request.SolveTurnstile(ctx, page, web.URL+"/lookalikes", "ua"); !errors.Is(err, types.ErrCaptchaSitekeyNotFound) {
			t.Errorf("SolveTurnstile error = %v, want ErrCaptchaSitekeyNotFound", err)
		}
		if got := web.createCount() - before; got != 0 {
			t.Errorf("createTask calls = %d, want 0", got)
		}
		if request.Remaining() != 3 {
			t.Errorf("Remaining() = %d, want 3", request.Remaining())
		}
	})

	// A real out-of-process iframe: parameters are captured in the child, the
	// token is delivered to the child's callback, and the capture cleans up.
	t.Run("out-of-process iframe lifecycle", func(t *testing.T) {
		br := startIsolatedBrowser(t)
		page := blankPage(t, br)
		captcha.InstallTurnstileInterceptor(ctx, page)
		done := captcha.InterceptorListenerDone(page)
		if done == nil {
			t.Fatal("no OOPIF listener was started")
		}
		navigate(ctx, t, page, web.URL+"/oopif-parent")
		waitFor(ctx, t, "the child frame to render", func() bool {
			return len(evalJSON[[]map[string]any](ctx, t, page, `window.messages`)) > 0
		})

		params, captured := captcha.ReadCapturedChallengeParams(ctx, page)
		if !captured {
			if targets, err := (proto.TargetGetTargets{}).Call(br); err == nil {
				for _, target := range targets.TargetInfos {
					t.Logf("target: type=%s url=%s", target.Type, target.URL)
				}
			}
			t.Fatalf("nothing captured from the out-of-process iframe (tracked children: %d)", captcha.InterceptorChildCount(page))
		}
		want := captcha.ChallengeParams{SiteKey: turnstileKey, Action: "managed", CData: "oopif-cdata", PageData: "oopif-pagedata"}
		if *params != want {
			t.Errorf("captured params = %+v, want %+v", *params, want)
		}
		if got := captcha.InterceptorChildCount(page); got != 1 {
			t.Errorf("tracked children = %d, want 1", got)
		}

		if !captcha.InjectCapturedCallback(ctx, page, hostileToken) {
			t.Fatal("InjectCapturedCallback = false")
		}
		waitFor(ctx, t, "the child to report the token", func() bool {
			for _, message := range evalJSON[[]map[string]any](ctx, t, page, `window.messages`) {
				if message["token"] == hostileToken {
					return true
				}
			}
			return false
		})

		// Navigating away destroys the child; it must be forgotten.
		navigate(ctx, t, page, web.URL+"/empty")
		waitFor(ctx, t, "the detached child to be pruned", func() bool {
			return captcha.InterceptorChildCount(page) == 0
		})
		if _, captured := captcha.ReadCapturedChallengeParams(ctx, page); captured {
			t.Error("params still reported after the child was destroyed")
		}

		captcha.RemoveTurnstileInterceptor(page)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the OOPIF listener goroutine did not exit after RemoveTurnstileInterceptor")
		}
		if captcha.InterceptorChildCount(page) != -1 {
			t.Error("interceptor state survived RemoveTurnstileInterceptor")
		}

		// With capture removed the page must still load cross-site iframes: an
		// auto-attach left behind would pause the child forever.
		navigate(ctx, t, page, web.URL+"/oopif-parent")
		waitFor(ctx, t, "a cross-site iframe to load after capture was removed", func() bool {
			return len(evalJSON[[]map[string]any](ctx, t, page, `window.messages`)) > 0
		})
	})

	t.Run("listener stops when its context ends", func(t *testing.T) {
		page := blankPage(t, br)
		requestCtx, endRequest := context.WithCancel(ctx)
		captcha.InstallTurnstileInterceptor(requestCtx, page)
		done := captcha.InterceptorListenerDone(page)
		if done == nil {
			t.Fatal("no OOPIF listener was started")
		}

		endRequest() // the request is abandoned; RemoveTurnstileInterceptor has not run yet
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the OOPIF listener outlived its request context")
		}
		captcha.RemoveTurnstileInterceptor(page)
		captcha.RemoveTurnstileInterceptor(page) // idempotent
	})
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(ctx context.Context, t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context ended waiting for %s", what)
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		case <-tick.C:
		}
	}
}

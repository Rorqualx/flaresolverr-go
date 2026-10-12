package captcha

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// createTaskProviders are the providers that speak the 2Captcha protocol. Every
// behavior below must hold for each, under its own name.
var createTaskProviders = []struct {
	name string
	make func(cfg TwoCaptchaConfig) CaptchaSolver
}{
	{"2captcha", func(cfg TwoCaptchaConfig) CaptchaSolver { return NewTwoCaptchaSolver(cfg) }},
	{"anticaptcha", func(cfg TwoCaptchaConfig) CaptchaSolver { return NewAntiCaptchaSolver(AntiCaptchaConfig(cfg)) }},
}

func fastConfig(baseURL string) TwoCaptchaConfig {
	return TwoCaptchaConfig{
		APIKey:       "test-key",
		BaseURL:      baseURL,
		Timeout:      testTimeout,
		PollInterval: testPollInterval,
	}
}

var turnstileReq = &TurnstileRequest{SiteKey: "0x4AAAAAAADnPIDROrmt1Wwj", PageURL: "https://example.com"}

func TestCreateTaskProviders_Identity(t *testing.T) {
	for _, p := range createTaskProviders {
		t.Run(p.name, func(t *testing.T) {
			solver := p.make(TwoCaptchaConfig{})
			if got := solver.Name(); got != p.name {
				t.Errorf("Name() = %q, want %q", got, p.name)
			}
			if solver.IsConfigured() {
				t.Error("IsConfigured() = true without a key")
			}
			if !p.make(TwoCaptchaConfig{APIKey: "k"}).IsConfigured() {
				t.Error("IsConfigured() = false with a key")
			}

			// An unconfigured provider refuses before any request, under its own name.
			_, err := solver.SolveTurnstile(context.Background(), turnstileReq)
			if err == nil || TaskCreated(err) {
				t.Fatalf("unconfigured solve: err = %v, TaskCreated = %v; want a not-created error", err, TaskCreated(err))
			}
			if !strings.Contains(err.Error(), p.name) {
				t.Errorf("error %q does not name provider %q", err, p.name)
			}
			if _, err := solver.Balance(context.Background()); err == nil {
				t.Error("Balance() without a key: want error")
			}
		})
	}
}

// TestCreateTaskProviders_ResultAndErrorsCarryOwnName is the regression test for
// anti-captcha reporting itself as "2captcha" in results and errors.
func TestCreateTaskProviders_ResultAndErrorsCarryOwnName(t *testing.T) {
	for _, p := range createTaskProviders {
		t.Run(p.name, func(t *testing.T) {
			fake := newFakeProvider(t)
			result, err := p.make(fastConfig(fake.URL)).SolveTurnstile(context.Background(), turnstileReq)
			if err != nil {
				t.Fatalf("SolveTurnstile() error = %v", err)
			}
			if result.Provider != p.name {
				t.Errorf("result.Provider = %q, want %q", result.Provider, p.name)
			}

			for _, script := range []struct {
				name   string
				create reply
				poll   reply
			}{
				{name: "rejected at createTask", create: ok(`{"errorId":1,"errorCode":"ERROR_ZERO_BALANCE"}`)},
				{name: "unknown error code", create: ok(`{"errorId":1,"errorCode":"ERROR_SOMETHING","errorDescription":"boom"}`)},
				{name: "timeout", create: ok(`{"errorId":0,"taskId":7}`), poll: ok(processing)},
			} {
				t.Run(script.name, func(t *testing.T) {
					fake := newFakeProvider(t).onCreate(script.create)
					cfg := fastConfig(fake.URL)
					if script.poll.body != "" {
						fake.onPoll(script.poll)
						cfg.Timeout = 40 * time.Millisecond
					}
					_, err := p.make(cfg).SolveTurnstile(context.Background(), turnstileReq)
					var captchaErr *types.CaptchaError
					if !errors.As(err, &captchaErr) {
						t.Fatalf("error = %v (%T), want a CaptchaError", err, err)
					}
					if captchaErr.Provider != p.name {
						t.Errorf("CaptchaError.Provider = %q, want %q", captchaErr.Provider, p.name)
					}
					other := "2captcha"
					if p.name == "2captcha" {
						other = "anticaptcha"
					}
					if strings.Contains(err.Error(), other) {
						t.Errorf("error %q names the wrong provider", err)
					}
				})
			}
		})
	}
}

func TestTwoCaptchaSolver_SolveTurnstile_Success(t *testing.T) {
	tests := []struct {
		name      string
		poll      string
		wantToken string
		wantCost  float64
		wantAgent string
	}{
		{
			name:      "cost as string",
			poll:      `{"errorId":0,"status":"ready","solution":{"token":"tok-1","userAgent":"Mozilla/5.0 worker"},"cost":"0.002"}`,
			wantToken: "tok-1",
			wantCost:  0.002,
			wantAgent: "Mozilla/5.0 worker",
		},
		{
			name:      "cost as number",
			poll:      `{"errorId":0,"status":"ready","solution":{"token":"tok-2"},"cost":0.00145}`,
			wantToken: "tok-2",
			wantCost:  0.00145,
		},
		{
			name:      "no cost",
			poll:      `{"errorId":0,"status":"ready","solution":{"token":"tok-3"}}`,
			wantToken: "tok-3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t).onPoll(ok(processing), ok(tt.poll))
			result, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveTurnstile(context.Background(), turnstileReq)
			if err != nil {
				t.Fatalf("SolveTurnstile() error = %v", err)
			}
			if result.Token != tt.wantToken {
				t.Errorf("Token = %q, want %q", result.Token, tt.wantToken)
			}
			if result.Cost != tt.wantCost {
				t.Errorf("Cost = %v, want %v", result.Cost, tt.wantCost)
			}
			if result.UserAgent != tt.wantAgent {
				t.Errorf("UserAgent = %q, want %q", result.UserAgent, tt.wantAgent)
			}
			if fake.createCount() != 1 {
				t.Errorf("createTask calls = %d, want 1", fake.createCount())
			}
		})
	}
}

// TestCreateTaskProviders_TurnstileTaskFields checks each dialect sends the
// managed-challenge parameters under the names its API documents.
func TestCreateTaskProviders_TurnstileTaskFields(t *testing.T) {
	req := &TurnstileRequest{
		SiteKey:   "0x4AAAAAAADnPIDROrmt1Wwj",
		PageURL:   "https://example.com/page",
		UserAgent: "Mozilla/5.0 page",
		Action:    "managed",
		CData:     "cdata-value",
		PageData:  "pagedata-value",
	}
	tests := []struct {
		provider string
		want     map[string]string
		absent   []string
	}{
		{
			provider: "2captcha",
			want: map[string]string{
				"type": "TurnstileTaskProxyless", "websiteURL": req.PageURL, "websiteKey": req.SiteKey,
				"action": "managed", "data": "cdata-value", "pagedata": "pagedata-value", "userAgent": "Mozilla/5.0 page",
			},
			absent: []string{"cData", "chlPageData"},
		},
		{
			provider: "anticaptcha",
			want: map[string]string{
				"type": "TurnstileTaskProxyless", "websiteURL": req.PageURL, "websiteKey": req.SiteKey,
				"action": "managed", "cData": "cdata-value", "chlPageData": "pagedata-value",
			},
			// anti-captcha rejects tasks that bring their own User-Agent.
			absent: []string{"data", "pagedata", "userAgent"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			fake := newFakeProvider(t)
			var solver CaptchaSolver
			for _, p := range createTaskProviders {
				if p.name == tt.provider {
					solver = p.make(fastConfig(fake.URL))
				}
			}
			if _, err := solver.SolveTurnstile(context.Background(), req); err != nil {
				t.Fatalf("SolveTurnstile() error = %v", err)
			}
			task := fake.lastTask(t)
			for key, want := range tt.want {
				if got, _ := task[key].(string); got != want {
					t.Errorf("task[%q] = %q, want %q", key, got, want)
				}
			}
			for _, key := range tt.absent {
				if _, present := task[key]; present {
					t.Errorf("task[%q] must not be sent to %s", key, tt.provider)
				}
			}
		})
	}

	t.Run("optional fields omitted when empty", func(t *testing.T) {
		fake := newFakeProvider(t)
		if _, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveTurnstile(context.Background(), turnstileReq); err != nil {
			t.Fatalf("SolveTurnstile() error = %v", err)
		}
		task := fake.lastTask(t)
		for _, key := range []string{"action", "data", "pagedata", "userAgent"} {
			if _, present := task[key]; present {
				t.Errorf("task[%q] sent although empty", key)
			}
		}
	})
}

// TestCreateTaskProviders_HCaptchaSolution covers both solution field names.
func TestCreateTaskProviders_HCaptchaSolution(t *testing.T) {
	tests := []struct {
		name     string
		solution string
		want     string
	}{
		{"gRecaptchaResponse", `{"gRecaptchaResponse":"P1_hcaptcha"}`, "P1_hcaptcha"},
		{"token", `{"token":"P1_token"}`, "P1_token"},
		{"both prefer token", `{"token":"P1_token","gRecaptchaResponse":"P1_other"}`, "P1_token"},
	}
	for _, p := range createTaskProviders {
		for _, tt := range tests {
			t.Run(p.name+"/"+tt.name, func(t *testing.T) {
				fake := newFakeProvider(t).onPoll(ok(`{"errorId":0,"status":"ready","solution":` + tt.solution + `}`))
				result, err := p.make(fastConfig(fake.URL)).SolveHCaptcha(context.Background(), &HCaptchaRequest{
					SiteKey: "10000000-ffff-ffff-ffff-000000000001",
					PageURL: "https://example.com",
				})
				if err != nil {
					t.Fatalf("SolveHCaptcha() error = %v", err)
				}
				if result.Token != tt.want {
					t.Errorf("Token = %q, want %q", result.Token, tt.want)
				}
				if got, _ := fake.lastTask(t)["type"].(string); got != "HCaptchaTaskProxyless" {
					t.Errorf("task type = %q, want HCaptchaTaskProxyless", got)
				}
			})
		}
	}
}

// TestTwoCaptchaSolver_CreateTaskRefusals: a definitive refusal creates no task,
// so the chain may try another provider without spending budget. hCaptcha being
// "not supported" is one of them.
func TestTwoCaptchaSolver_CreateTaskRefusals(t *testing.T) {
	tests := []struct {
		name    string
		create  reply
		wantErr error
	}{
		{"bad key", ok(`{"errorId":1,"errorCode":"ERROR_KEY_DOES_NOT_EXIST"}`), types.ErrCaptchaSolverRejected},
		{"zero balance", ok(`{"errorId":10,"errorCode":"ERROR_ZERO_BALANCE"}`), types.ErrCaptchaSolverBalance},
		{"task not supported", ok(`{"errorId":1,"errorCode":"ERROR_TASK_NOT_SUPPORTED"}`), types.ErrCaptchaSolverRejected},
		{"task absent", ok(`{"errorId":1,"errorCode":"ERROR_TASK_ABSENT"}`), types.ErrCaptchaSolverRejected},
		{"unknown code", ok(`{"errorId":1,"errorCode":"ERROR_NEW","errorDescription":"new failure"}`), types.ErrCaptchaSolverRejected},
		{"no task id", ok(`{"errorId":0}`), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t).onCreate(tt.create)
			_, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveHCaptcha(context.Background(), &HCaptchaRequest{
				SiteKey: "10000000-ffff-ffff-ffff-000000000001", PageURL: "https://example.com",
			})
			if err == nil {
				t.Fatal("want error")
			}
			if TaskCreated(err) {
				t.Errorf("TaskCreated(%v) = true, want false", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if fake.pollCount() != 0 {
				t.Errorf("polled %d times after a refused createTask", fake.pollCount())
			}
		})
	}
}

// TestTwoCaptchaSolver_CreateTaskAmbiguous: when it is unknown whether the
// provider accepted the task, it counts as created (and so as spent budget).
func TestTwoCaptchaSolver_CreateTaskAmbiguous(t *testing.T) {
	tests := []struct {
		name   string
		create reply
	}{
		{"http 500", reply{status: http.StatusInternalServerError, body: "oops"}},
		{"http 502 html", reply{status: http.StatusBadGateway, body: "<html>Bad Gateway</html>"}},
		{"http 429", reply{status: http.StatusTooManyRequests, body: "slow down"}},
		{"html with 200", ok("<html>maintenance</html>")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t).onCreate(tt.create)
			_, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveTurnstile(context.Background(), turnstileReq)
			if err == nil {
				t.Fatal("want error")
			}
			if !TaskCreated(err) {
				t.Errorf("TaskCreated(%v) = false, want true (ambiguous)", err)
			}
			if fake.createCount() != 1 {
				t.Errorf("createTask calls = %d, want exactly 1 (no blind retry of a purchase)", fake.createCount())
			}
		})
	}

	t.Run("connection refused creates nothing", func(t *testing.T) {
		_, err := NewTwoCaptchaSolver(fastConfig(closedServerURL())).SolveTurnstile(context.Background(), turnstileReq)
		if err == nil {
			t.Fatal("want error")
		}
		if TaskCreated(err) {
			t.Errorf("TaskCreated(%v) = true, want false: the request never left", err)
		}
	})
}

func TestTwoCaptchaSolver_PollErrors(t *testing.T) {
	t.Run("error code while polling is terminal and counts as created", func(t *testing.T) {
		fake := newFakeProvider(t).onPoll(ok(`{"errorId":1,"errorCode":"ERROR_CAPTCHA_UNSOLVABLE"}`))
		_, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveTurnstile(context.Background(), turnstileReq)
		if !errors.Is(err, types.ErrCaptchaSolverRejected) {
			t.Fatalf("error = %v, want ErrCaptchaSolverRejected", err)
		}
		if !TaskCreated(err) {
			t.Error("TaskCreated = false, want true")
		}
		if fake.pollCount() != 1 {
			t.Errorf("polls = %d, want 1", fake.pollCount())
		}
	})

	t.Run("ready without a token is an error", func(t *testing.T) {
		fake := newFakeProvider(t).onPoll(ok(`{"errorId":0,"status":"ready","solution":{}}`))
		_, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveTurnstile(context.Background(), turnstileReq)
		if !errors.Is(err, types.ErrCaptchaSolverRejected) {
			t.Fatalf("error = %v, want ErrCaptchaSolverRejected", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		fake := newFakeProvider(t).onPoll(ok(processing))
		cfg := fastConfig(fake.URL)
		cfg.Timeout = 60 * time.Millisecond
		_, err := NewTwoCaptchaSolver(cfg).SolveTurnstile(context.Background(), turnstileReq)
		if !errors.Is(err, types.ErrCaptchaSolverTimeout) {
			t.Fatalf("error = %v, want ErrCaptchaSolverTimeout", err)
		}
		if !TaskCreated(err) {
			t.Error("TaskCreated = false, want true")
		}
		if fake.pollCount() < 2 {
			t.Errorf("polls = %d, want several before the timeout", fake.pollCount())
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		fake := newFakeProvider(t).onPoll(ok(processing))
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).SolveTurnstile(ctx, turnstileReq)
		if err == nil {
			t.Fatal("want error")
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("returned after %v, want promptly after cancellation", elapsed)
		}
	})
}

func TestTwoCaptchaSolver_Balance(t *testing.T) {
	fake := newFakeProvider(t)
	balance, err := NewTwoCaptchaSolver(fastConfig(fake.URL)).Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error = %v", err)
	}
	if balance != 5.5 {
		t.Errorf("Balance() = %v, want 5.5", balance)
	}
}

// TestCreateTaskProviders_ErrorDescriptionDoesNotLeakKey: a provider that echoes
// the key in its description must not get it into our error.
func TestCreateTaskProviders_ErrorDescriptionDoesNotLeakKey(t *testing.T) {
	const marker = "marker-value-0123456789"
	for _, p := range createTaskProviders {
		t.Run(p.name, func(t *testing.T) {
			fake := newFakeProvider(t).onCreate(ok(
				`{"errorId":1,"errorCode":"ERROR_ODD","errorDescription":"account for ` + marker + ` is odd"}`))
			cfg := fastConfig(fake.URL)
			cfg.APIKey = marker
			_, err := p.make(cfg).SolveTurnstile(context.Background(), turnstileReq)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("error leaks the API key: %v", err)
			}
		})
	}
}

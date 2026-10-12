package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestDoJSON(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		wantErr       bool
		wantTransient bool
		wantValue     string
	}{
		{name: "ok", status: 200, body: `{"value":"x"}`, wantValue: "x"},
		{name: "json error body with 400 is decoded, not transient", status: 400, body: `{"value":"denied"}`, wantValue: "denied"},
		{name: "500", status: 500, body: `{"value":"x"}`, wantErr: true, wantTransient: true},
		{name: "502 html", status: 502, body: "<html>bad gateway</html>", wantErr: true, wantTransient: true},
		{name: "503", status: 503, body: "", wantErr: true, wantTransient: true},
		{name: "429", status: 429, body: `{"value":"x"}`, wantErr: true, wantTransient: true},
		{name: "html with 200", status: 200, body: "<html>maintenance</html>", wantErr: true, wantTransient: true},
		{name: "empty body", status: 200, body: "", wantErr: true, wantTransient: true},
		{name: "oversized body is not retried", status: 200, body: `{"value":"` + strings.Repeat("a", maxProviderResponseBytes) + `"}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			var out struct {
				Value string `json:"value"`
			}
			err := doJSON(context.Background(), server.Client(), http.MethodPost, server.URL, map[string]string{"k": "v"}, &out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("doJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && isTransient(err) != tt.wantTransient {
				t.Errorf("isTransient(%v) = %v, want %v", err, isTransient(err), tt.wantTransient)
			}
			if out.Value != tt.wantValue {
				t.Errorf("decoded value = %q, want %q", truncate(out.Value, 20), tt.wantValue)
			}
		})
	}
}

// TestDoJSON_ErrorsNeverCarryTheURL: 9kw puts the API key in the query string,
// so no error may include the request URL.
func TestDoJSON_ErrorsNeverCarryTheURL(t *testing.T) {
	const marker = "marker-value-0123456789"
	tests := []struct {
		name string
		url  string
	}{
		{"connection refused", closedServerURL() + "/index.cgi?apikey=" + marker},
		{"unparseable url", "http://[::1]:namedport/?apikey=" + marker},
		{"control character", "http://example.invalid/\x7f?apikey=" + marker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := doJSON(context.Background(), http.DefaultClient, http.MethodGet, tt.url, nil, &out)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "apikey") {
				t.Errorf("error leaks the request URL: %v", err)
			}
		})
	}
}

func TestDoJSON_SendsJSONBody(t *testing.T) {
	var gotType, gotMethod string
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		gotMethod = r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	var out map[string]any
	if err := doJSON(context.Background(), server.Client(), http.MethodPost, server.URL, map[string]string{"clientKey": "k"}, &out); err != nil {
		t.Fatalf("doJSON() error = %v", err)
	}
	if gotMethod != http.MethodPost || gotType != "application/json" || gotBody["clientKey"] != "k" {
		t.Errorf("request = %s %q %v", gotMethod, gotType, gotBody)
	}
}

// pollScript drives pollTask with a scripted sequence of fetch outcomes.
type pollStep struct {
	ready bool
	err   error
}

func runPoll(ctx context.Context, timeout time.Duration, steps ...pollStep) (calls int, err error) {
	var n atomic.Int32
	_, err = pollTask(ctx, pollConfig{provider: "fake", taskID: "t-1", timeout: timeout, interval: time.Millisecond},
		func(context.Context) (string, bool, error) {
			i := int(n.Add(1))
			step := steps[min(i, len(steps))-1]
			return "result", step.ready, step.err
		})
	return int(n.Load()), err
}

func TestPollTask(t *testing.T) {
	transient := asTransient(errors.New("provider returned HTTP 502"))
	permanent := types.NewCaptchaRejectedError("fake", "ERROR_CAPTCHA_UNSOLVABLE", "unsolvable")
	pending, ready := pollStep{}, pollStep{ready: true}

	tests := []struct {
		name      string
		steps     []pollStep
		timeout   time.Duration
		wantCalls int
		wantErr   error // nil means success
		wantAny   bool  // an error, of no particular kind
	}{
		{name: "ready at once", steps: []pollStep{ready}, wantCalls: 1},
		{name: "pending then ready", steps: []pollStep{pending, pending, ready}, wantCalls: 3},
		{name: "one 502 then ready does not abandon the task", steps: []pollStep{{err: transient}, ready}, wantCalls: 2},
		{name: "three transient in a row then ready", steps: []pollStep{{err: transient}, {err: transient}, {err: transient}, ready}, wantCalls: 4},
		{name: "four transient in a row give up", steps: []pollStep{{err: transient}}, wantCalls: maxTransientPollErrors + 1, wantErr: types.ErrCaptchaSolverRejected},
		{name: "a good poll resets the transient count", steps: []pollStep{
			{err: transient}, {err: transient}, {err: transient}, pending,
			{err: transient}, {err: transient}, {err: transient}, ready,
		}, wantCalls: 8},
		{name: "permanent error stops at once", steps: []pollStep{pending, {err: permanent}}, wantCalls: 2, wantErr: types.ErrCaptchaSolverRejected},
		{name: "never ready times out", steps: []pollStep{pending}, timeout: 30 * time.Millisecond, wantErr: types.ErrCaptchaSolverTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeout := tt.timeout
			if timeout == 0 {
				timeout = testTimeout
			}
			calls, err := runPoll(context.Background(), timeout, tt.steps...)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Fatalf("pollTask() error = %v, want success", err)
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Fatalf("pollTask() error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if tt.wantCalls != 0 && calls != tt.wantCalls {
				t.Errorf("fetch calls = %d, want %d", calls, tt.wantCalls)
			}
			var captchaErr *types.CaptchaError
			if err != nil && (!errors.As(err, &captchaErr) || captchaErr.Provider != "fake") {
				t.Errorf("error = %#v, want a CaptchaError naming the provider", err)
			}
		})
	}

	t.Run("canceled context ends the poll as a timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls, err := runPoll(ctx, testTimeout, pending)
		if !errors.Is(err, types.ErrCaptchaSolverTimeout) {
			t.Fatalf("error = %v, want ErrCaptchaSolverTimeout", err)
		}
		if calls != 0 {
			t.Errorf("fetch calls = %d after cancellation, want 0", calls)
		}
	})
}

// TestPollTask_FirstPollAfterOneInterval is the regression test for the first
// poll being delayed by two intervals (a ticker was drained once before use).
func TestPollTask_FirstPollAfterOneInterval(t *testing.T) {
	const interval = 250 * time.Millisecond

	started := time.Now()
	var first time.Duration
	_, err := pollTask(context.Background(), pollConfig{provider: "fake", taskID: "t", timeout: testTimeout, interval: interval},
		func(context.Context) (string, bool, error) {
			first = time.Since(started)
			return "", true, nil
		})
	if err != nil {
		t.Fatalf("pollTask() error = %v", err)
	}
	if first < interval {
		t.Errorf("first poll after %v, want at least one interval (%v)", first, interval)
	}
	if first >= 2*interval {
		t.Errorf("first poll after %v, want well under two intervals (%v)", first, 2*interval)
	}
}

// TestProviders_FirstPollTiming checks the same through each real provider.
func TestProviders_FirstPollTiming(t *testing.T) {
	const interval = 250 * time.Millisecond

	solvers := map[string]func(baseURL string) (CaptchaSolver, reply){
		"2captcha": func(baseURL string) (CaptchaSolver, reply) {
			cfg := fastConfig(baseURL)
			cfg.PollInterval = interval
			return NewTwoCaptchaSolver(cfg), ok(`{"errorId":0,"taskId":1}`)
		},
		"anticaptcha": func(baseURL string) (CaptchaSolver, reply) {
			cfg := fastConfig(baseURL)
			cfg.PollInterval = interval
			return NewAntiCaptchaSolver(AntiCaptchaConfig(cfg)), ok(`{"errorId":0,"taskId":1}`)
		},
		"capsolver": func(baseURL string) (CaptchaSolver, reply) {
			return NewCapSolverSolver(CapSolverConfig{APIKey: "k", BaseURL: baseURL, Timeout: testTimeout, PollInterval: interval}),
				ok(capSolverCreated)
		},
	}
	for name, build := range solvers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeProvider(t)
			solver, created := build(fake.URL)
			fake.onCreate(created)
			if _, err := solver.SolveTurnstile(context.Background(), turnstileReq); err != nil {
				t.Fatalf("SolveTurnstile() error = %v", err)
			}
			delay := fake.firstPollDelay(t)
			if delay < interval-20*time.Millisecond || delay >= 2*interval {
				t.Errorf("first poll %v after createTask, want about one interval (%v)", delay, interval)
			}
		})
	}
}

// TestProviders_TransientPollErrorsDoNotAbandonTask drives each provider through
// a flaky poll: the task was paid for, so one bad response must not lose it.
func TestProviders_TransientPollErrorsDoNotAbandonTask(t *testing.T) {
	flaky := map[string]reply{
		"502":            {status: http.StatusBadGateway, body: "<html>502 Bad Gateway</html>"},
		"500":            {status: http.StatusInternalServerError, body: "{}"},
		"429":            {status: http.StatusTooManyRequests, body: `{"errorId":0,"status":"ready","solution":{"token":"ignored"}}`},
		"html with 200":  ok("<!doctype html><title>Just a moment...</title>"),
		"truncated json": ok(`{"errorId":0,"status":"rea`),
	}
	for _, provider := range []string{"2captcha", "anticaptcha", "capsolver"} {
		for name, bad := range flaky {
			t.Run(provider+"/"+name, func(t *testing.T) {
				fake := newFakeProvider(t).onPoll(bad, bad, readyToken("survived"))
				var solver CaptchaSolver
				switch provider {
				case "2captcha":
					solver = NewTwoCaptchaSolver(fastConfig(fake.URL))
				case "anticaptcha":
					solver = NewAntiCaptchaSolver(AntiCaptchaConfig(fastConfig(fake.URL)))
				default:
					fake.onCreate(ok(capSolverCreated))
					solver = fastCapSolver(fake.URL)
				}

				result, err := solver.SolveTurnstile(context.Background(), turnstileReq)
				if err != nil {
					t.Fatalf("SolveTurnstile() error = %v, want the task to survive two bad polls", err)
				}
				if result.Token != "survived" {
					t.Errorf("Token = %q, want %q", result.Token, "survived")
				}
				if fake.createCount() != 1 {
					t.Errorf("createTask calls = %d, want 1 (the task must not be re-bought)", fake.createCount())
				}
				if fake.pollCount() != 3 {
					t.Errorf("polls = %d, want 3", fake.pollCount())
				}
			})
		}

		t.Run(provider+"/persistent failure gives up", func(t *testing.T) {
			bad := reply{status: http.StatusBadGateway, body: "bad gateway"}
			fake := newFakeProvider(t).onPoll(bad)
			var solver CaptchaSolver
			switch provider {
			case "2captcha":
				solver = NewTwoCaptchaSolver(fastConfig(fake.URL))
			case "anticaptcha":
				solver = NewAntiCaptchaSolver(AntiCaptchaConfig(fastConfig(fake.URL)))
			default:
				fake.onCreate(ok(capSolverCreated))
				solver = fastCapSolver(fake.URL)
			}

			_, err := solver.SolveTurnstile(context.Background(), turnstileReq)
			if err == nil {
				t.Fatal("want error after persistent poll failures")
			}
			if errors.Is(err, types.ErrCaptchaSolverTimeout) {
				t.Errorf("error = %v, want a give-up error rather than a timeout", err)
			}
			if !TaskCreated(err) {
				t.Error("TaskCreated = false, want true")
			}
			if got := fake.pollCount(); got != maxTransientPollErrors+1 {
				t.Errorf("polls = %d, want %d", got, maxTransientPollErrors+1)
			}
		})
	}
}

func TestFlexString(t *testing.T) {
	tests := []struct {
		json      string
		want      string
		wantFloat float64
		wantErr   bool
	}{
		{json: `"0.002"`, want: "0.002", wantFloat: 0.002},
		{json: `0.002`, want: "0.002", wantFloat: 0.002},
		{json: `130875948`, want: "130875948", wantFloat: 130875948},
		{json: `"130875948"`, want: "130875948", wantFloat: 130875948},
		{json: `1`, want: "1", wantFloat: 1},
		{json: `""`, want: ""},
		{json: `null`, want: ""},
		{json: `"abc"`, want: "abc"},
		{json: `{}`, wantErr: true},
		{json: `[1]`, wantErr: true},
		{json: `true`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			var out struct {
				V flexString `json:"v"`
			}
			err := json.Unmarshal([]byte(`{"v":`+tt.json+`}`), &out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if string(out.V) != tt.want || out.V.float() != tt.wantFloat {
				t.Errorf("got %q / %v, want %q / %v", out.V, out.V.float(), tt.want, tt.wantFloat)
			}
		})
	}
}

// netDialError is what a refused connection looks like underneath http.Client.
var netDialError = net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}

func TestTaskCreated(t *testing.T) {
	base := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"plain error is ambiguous", base, true},
		{"not created", notCreated(base), false},
		{"not created, wrapped", errors.Join(errors.New("outer"), notCreated(base)), false},
		{"dial failure never left", createFailure(asTransient(&netDialError)), false},
		{"http 500 is ambiguous", createFailure(asTransient(errors.New("provider returned HTTP 500"))), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TaskCreated(tt.err); got != tt.want {
				t.Errorf("TaskCreated() = %v, want %v", got, tt.want)
			}
		})
	}
	if !errors.Is(notCreated(base), base) {
		t.Error("notCreated must keep the wrapped error reachable")
	}
}

func TestScrub(t *testing.T) {
	tests := []struct {
		text, secret, want string
	}{
		{"key abc123 is unknown", "abc123", "key [redacted] is unknown"},
		{"abc123 and abc123", "abc123", "[redacted] and [redacted]"},
		{"nothing here", "abc123", "nothing here"},
		{"empty secret changes nothing", "", "empty secret changes nothing"},
	}
	for _, tt := range tests {
		if got := scrub(tt.text, tt.secret); got != tt.want {
			t.Errorf("scrub(%q, %q) = %q, want %q", tt.text, tt.secret, got, tt.want)
		}
	}
}

package captcha

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func fastCapSolver(baseURL string) *CapSolverSolver {
	return NewCapSolverSolver(CapSolverConfig{
		APIKey:       "test-key",
		BaseURL:      baseURL,
		Timeout:      testTimeout,
		PollInterval: testPollInterval,
	})
}

// capSolverCreated is CapSolver's createTask answer: a UUID task id, status idle.
const capSolverCreated = `{"errorId":0,"errorCode":null,"errorDescription":null,"status":"idle","taskId":"61138bb6-19fb-11ec-a9c8-0242ac110006"}`

func TestCapSolverSolver_Identity(t *testing.T) {
	solver := NewCapSolverSolver(CapSolverConfig{})
	if got := solver.Name(); got != "capsolver" {
		t.Errorf("Name() = %q, want %q", got, "capsolver")
	}
	if solver.IsConfigured() {
		t.Error("IsConfigured() = true without a key")
	}
	if !NewCapSolverSolver(CapSolverConfig{APIKey: "k"}).IsConfigured() {
		t.Error("IsConfigured() = false with a key")
	}

	_, err := solver.SolveTurnstile(context.Background(), turnstileReq)
	if err == nil || TaskCreated(err) {
		t.Errorf("unconfigured solve: err = %v, want a not-created error", err)
	}
	if _, err := solver.Balance(context.Background()); err == nil {
		t.Error("Balance() without a key: want error")
	}
}

// TestCapSolverSolver_RefusesManagedChallenge: with chlPageData present CapSolver
// must refuse before any HTTP call. Its proxyless Turnstile task cannot carry
// the challenge-page data, so a purchase would be wasted.
func TestCapSolverSolver_RefusesManagedChallenge(t *testing.T) {
	fake := newFakeProvider(t).onCreate(ok(capSolverCreated))

	_, err := fastCapSolver(fake.URL).SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey:  "0x4AAAAAAADnPIDROrmt1Wwj",
		PageURL:  "https://example.com",
		Action:   "managed",
		CData:    "cdata",
		PageData: "challenge-page-data",
	})
	if err == nil {
		t.Fatal("want a refusal")
	}
	if TaskCreated(err) {
		t.Error("TaskCreated = true, want false")
	}
	var captchaErr *types.CaptchaError
	if !errors.As(err, &captchaErr) || captchaErr.Code != "UNSUPPORTED" || captchaErr.Provider != "capsolver" {
		t.Errorf("error = %#v, want capsolver UNSUPPORTED", captchaErr)
	}
	if fake.createCount() != 0 || fake.pollCount() != 0 {
		t.Errorf("HTTP calls: createTask=%d getTaskResult=%d, want 0 and 0", fake.createCount(), fake.pollCount())
	}
}

func TestCapSolverSolver_SolveTurnstile(t *testing.T) {
	tests := []struct {
		name      string
		create    reply
		polls     []reply
		wantToken string
		wantAgent string
		wantPolls int
		wantErr   error
	}{
		{
			name:   "idle then processing then ready",
			create: ok(capSolverCreated),
			polls: []reply{
				ok(`{"errorId":0,"status":"idle"}`),
				ok(`{"errorId":0,"status":"processing"}`),
				ok(`{"errorId":0,"status":"ready","solution":{"token":"cs-token","userAgent":"Mozilla/5.0 cs"}}`),
			},
			wantToken: "cs-token",
			wantAgent: "Mozilla/5.0 cs",
			wantPolls: 3,
		},
		{
			name:      "unknown status keeps polling",
			create:    ok(capSolverCreated),
			polls:     []reply{ok(`{"errorId":0,"status":"queued"}`), readyToken("cs-late")},
			wantToken: "cs-late",
			wantPolls: 2,
		},
		{
			name:      "createTask answers ready with the solution",
			create:    ok(`{"errorId":0,"status":"ready","taskId":"t-1","solution":{"token":"cs-sync"}}`),
			wantToken: "cs-sync",
			wantPolls: 0,
		},
		{
			name:      "failed status is terminal",
			create:    ok(capSolverCreated),
			polls:     []reply{ok(`{"errorId":0,"status":"failed"}`)},
			wantPolls: 1,
			wantErr:   types.ErrCaptchaSolverRejected,
		},
		{
			name:      "error while polling is terminal",
			create:    ok(capSolverCreated),
			polls:     []reply{ok(`{"errorId":1,"errorCode":"ERROR_CAPTCHA_UNSOLVABLE"}`)},
			wantPolls: 1,
			wantErr:   types.ErrCaptchaSolverRejected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t).onCreate(tt.create)
			if len(tt.polls) > 0 {
				fake.onPoll(tt.polls...)
			}
			result, err := fastCapSolver(fake.URL).SolveTurnstile(context.Background(), turnstileReq)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want errors.Is %v", err, tt.wantErr)
				}
				if !TaskCreated(err) {
					t.Error("TaskCreated = false after a task was created")
				}
			} else {
				if err != nil {
					t.Fatalf("SolveTurnstile() error = %v", err)
				}
				if result.Token != tt.wantToken || result.UserAgent != tt.wantAgent || result.Provider != "capsolver" {
					t.Errorf("result = %+v, want token %q agent %q provider capsolver", result, tt.wantToken, tt.wantAgent)
				}
			}
			if fake.pollCount() != tt.wantPolls {
				t.Errorf("polls = %d, want %d", fake.pollCount(), tt.wantPolls)
			}
			if fake.createCount() != 1 {
				t.Errorf("createTask calls = %d, want 1", fake.createCount())
			}
		})
	}
}

func TestCapSolverSolver_TaskFields(t *testing.T) {
	t.Run("standalone widget metadata", func(t *testing.T) {
		fake := newFakeProvider(t).onCreate(ok(capSolverCreated))
		_, err := fastCapSolver(fake.URL).SolveTurnstile(context.Background(), &TurnstileRequest{
			SiteKey: "0x4AAAAAAADnPIDROrmt1Wwj", PageURL: "https://example.com", Action: "login", CData: "custom-data",
		})
		if err != nil {
			t.Fatalf("SolveTurnstile() error = %v", err)
		}
		task := fake.lastTask(t)
		if got, _ := task["type"].(string); got != "AntiTurnstileTaskProxyLess" {
			t.Errorf("type = %q", got)
		}
		metadata, _ := task["metadata"].(map[string]any)
		if metadata["action"] != "login" || metadata["cdata"] != "custom-data" {
			t.Errorf("metadata = %v, want action=login cdata=custom-data", metadata)
		}
	})

	t.Run("no metadata without action or cdata", func(t *testing.T) {
		fake := newFakeProvider(t).onCreate(ok(capSolverCreated))
		if _, err := fastCapSolver(fake.URL).SolveTurnstile(context.Background(), turnstileReq); err != nil {
			t.Fatalf("SolveTurnstile() error = %v", err)
		}
		if _, present := fake.lastTask(t)["metadata"]; present {
			t.Error("metadata sent although empty")
		}
	})

	t.Run("hcaptcha accepts gRecaptchaResponse", func(t *testing.T) {
		fake := newFakeProvider(t).onCreate(ok(capSolverCreated)).
			onPoll(ok(`{"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":"P1_cs"}}`))
		result, err := fastCapSolver(fake.URL).SolveHCaptcha(context.Background(), &HCaptchaRequest{
			SiteKey: "10000000-ffff-ffff-ffff-000000000001", PageURL: "https://example.com",
		})
		if err != nil {
			t.Fatalf("SolveHCaptcha() error = %v", err)
		}
		if result.Token != "P1_cs" {
			t.Errorf("Token = %q, want P1_cs", result.Token)
		}
		if got, _ := fake.lastTask(t)["type"].(string); got != "HCaptchaTaskProxyLess" {
			t.Errorf("type = %q", got)
		}
	})
}

// TestCapSolverSolver_CreateTaskRefusals: CapSolver dropped hCaptcha support at
// one point; whatever it answers, a refused createTask must read as "nothing
// bought" so the chain moves on to the next provider.
func TestCapSolverSolver_CreateTaskRefusals(t *testing.T) {
	tests := []struct {
		name    string
		create  string
		wantErr error
	}{
		{"zero balance", `{"errorId":1,"errorCode":"ERROR_ZERO_BALANCE","errorDescription":"Insufficient balance"}`, types.ErrCaptchaSolverBalance},
		{"invalid key", `{"errorId":1,"errorCode":"ERROR_KEY_DENIED"}`, types.ErrCaptchaSolverRejected},
		{"task not supported", `{"errorId":1,"errorCode":"ERROR_TASK_NOT_SUPPORTED"}`, types.ErrCaptchaSolverRejected},
		{"invalid task data", `{"errorId":1,"errorCode":"ERROR_INVALID_TASK_DATA","errorDescription":"task type is not supported"}`, types.ErrCaptchaSolverRejected},
		{"unknown code", `{"errorId":1,"errorCode":"ERROR_NEW","errorDescription":"something new"}`, types.ErrCaptchaSolverRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeProvider(t).onCreate(ok(tt.create))
			_, err := fastCapSolver(fake.URL).SolveHCaptcha(context.Background(), &HCaptchaRequest{
				SiteKey: "10000000-ffff-ffff-ffff-000000000001", PageURL: "https://example.com",
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want errors.Is %v", err, tt.wantErr)
			}
			if TaskCreated(err) {
				t.Error("TaskCreated = true, want false")
			}
			var captchaErr *types.CaptchaError
			if !errors.As(err, &captchaErr) || captchaErr.Provider != "capsolver" {
				t.Errorf("CaptchaError = %#v, want provider capsolver", captchaErr)
			}
		})
	}
}

func TestCapSolverSolver_Timeout(t *testing.T) {
	fake := newFakeProvider(t).onCreate(ok(capSolverCreated)).onPoll(ok(`{"errorId":0,"status":"processing"}`))
	solver := NewCapSolverSolver(CapSolverConfig{
		APIKey: "test-key", BaseURL: fake.URL, Timeout: 50 * time.Millisecond, PollInterval: testPollInterval,
	})
	_, err := solver.SolveTurnstile(context.Background(), turnstileReq)
	if !errors.Is(err, types.ErrCaptchaSolverTimeout) {
		t.Fatalf("error = %v, want ErrCaptchaSolverTimeout", err)
	}
}

func TestCapSolverSolver_Balance(t *testing.T) {
	fake := newFakeProvider(t)
	balance, err := fastCapSolver(fake.URL).Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error = %v", err)
	}
	if balance != 5.5 {
		t.Errorf("Balance() = %v, want 5.5", balance)
	}
}

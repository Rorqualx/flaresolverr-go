package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestNineKwSolver_Name(t *testing.T) {
	solver := NewNineKwSolver(NineKwConfig{})
	if got := solver.Name(); got != "9kw" {
		t.Errorf("Name() = %q, want %q", got, "9kw")
	}
}

func TestNineKwSolver_Registered(t *testing.T) {
	if GetFactory("9kw") == nil {
		t.Fatal("9kw provider not registered in the global registry")
	}
}

func TestNineKwSolver_IsConfigured(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
		want   bool
	}{
		{name: "configured with key", apiKey: "test-api-key", want: true},
		{name: "not configured without key", apiKey: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solver := NewNineKwSolver(NineKwConfig{APIKey: tt.apiKey})
			if got := solver.IsConfigured(); got != tt.want {
				t.Errorf("IsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNineKwSolver_SolveTurnstile_Unsupported verifies 9kw reports Turnstile as
// unsupported (so SolverChain falls through to a Turnstile-capable provider)
// rather than silently failing or blocking.
func TestNineKwSolver_SolveTurnstile_Unsupported(t *testing.T) {
	solver := NewNineKwSolver(NineKwConfig{APIKey: "test-key"})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "0x4AAAAAAA",
		PageURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected unsupported error for Turnstile on 9kw")
	}

	var captchaErr *types.CaptchaError
	if !containsCaptchaError(err, &captchaErr) {
		t.Fatalf("expected CaptchaError, got %T", err)
	}
	if captchaErr.Code != "UNSUPPORTED" {
		t.Errorf("Code = %q, want %q", captchaErr.Code, "UNSUPPORTED")
	}
}

func TestNineKwSolver_SolveHCaptcha_Success(t *testing.T) {
	const wantToken = "P0_eyJ0eXAfor-hcaptcha" //nolint:gosec // test fixture, not a real credential
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("action") {
		case "usercaptchaupload":
			// Verify the interactive hCaptcha submission is well-formed.
			if q.Get("oldsource") != "hcaptcha" {
				t.Errorf("oldsource = %q, want %q", q.Get("oldsource"), "hcaptcha")
			}
			if q.Get("interactive") != "1" {
				t.Errorf("interactive = %q, want %q", q.Get("interactive"), "1")
			}
			if q.Get("file-upload-01") != "10000000-ffff-ffff-ffff-000000000001" {
				t.Errorf("file-upload-01 = %q", q.Get("file-upload-01"))
			}
			w.Write([]byte(`{"captchaid":"130875948","status":{"success":true}}`))
		case "usercaptchacorrectdata":
			polls++
			if polls == 1 {
				// Still being solved.
				w.Write([]byte(`{"answer":"","try_again":1,"message":"NO DATA"}`))
				return
			}
			w.Write([]byte(`{"answer":"` + wantToken + `","try_again":0,"credits":30748,"message":"OK"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	solver := NewNineKwSolver(NineKwConfig{
		APIKey:       "test-key",
		BaseURL:      server.URL,
		Timeout:      30 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})

	result, err := solver.SolveHCaptcha(context.Background(), &HCaptchaRequest{
		SiteKey: "10000000-ffff-ffff-ffff-000000000001",
		PageURL: "https://example.com",
	})
	if err != nil {
		t.Fatalf("SolveHCaptcha() error = %v", err)
	}
	if result.Token != wantToken {
		t.Errorf("Token = %q, want %q", result.Token, wantToken)
	}
	if result.Provider != "9kw" {
		t.Errorf("Provider = %q, want %q", result.Provider, "9kw")
	}
	if polls < 2 {
		t.Errorf("expected to poll at least twice, got %d", polls)
	}
}

func TestNineKwSolver_SolveHCaptcha_NoWorkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("action") {
		case "usercaptchaupload":
			w.Write([]byte(`{"captchaid":"42"}`))
		case "usercaptchacorrectdata":
			w.Write([]byte(`{"answer":"ERROR NO USER","try_again":0}`))
		}
	}))
	defer server.Close()

	solver := NewNineKwSolver(NineKwConfig{
		APIKey:       "test-key",
		BaseURL:      server.URL,
		Timeout:      30 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})

	_, err := solver.SolveHCaptcha(context.Background(), &HCaptchaRequest{
		SiteKey: "sitekey",
		PageURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error when no workers are available")
	}
}

func TestNineKwSolver_SolveHCaptcha_SubmitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":"0003 Active API key not found"}`))
	}))
	defer server.Close()

	solver := NewNineKwSolver(NineKwConfig{
		APIKey:       "bad-key",
		BaseURL:      server.URL,
		Timeout:      10 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})

	_, err := solver.SolveHCaptcha(context.Background(), &HCaptchaRequest{
		SiteKey: "sitekey",
		PageURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}
	var captchaErr *types.CaptchaError
	if !containsCaptchaError(err, &captchaErr) {
		t.Errorf("expected CaptchaError, got %T", err)
	}
}

func TestNineKwSolver_SolveHCaptcha_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("action") {
		case "usercaptchaupload":
			w.Write([]byte(`{"captchaid":"99"}`))
		case "usercaptchacorrectdata":
			// Never completes.
			w.Write([]byte(`{"answer":"","try_again":1}`))
		}
	}))
	defer server.Close()

	solver := NewNineKwSolver(NineKwConfig{
		APIKey:       "test-key",
		BaseURL:      server.URL,
		Timeout:      30 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	_, err := solver.SolveHCaptcha(ctx, &HCaptchaRequest{
		SiteKey: "sitekey",
		PageURL: "https://example.com",
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestNineKwSolver_Balance(t *testing.T) {
	tests := []struct {
		name string
		body string
		want float64
	}{
		{name: "numeric credits", body: `{"credits":54514,"message":"OK"}`, want: 54514},
		{name: "string credits", body: `{"credits":"123","message":"OK"}`, want: 123},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("action"); got != "usercaptchaguthaben" {
					t.Errorf("action = %q, want usercaptchaguthaben", got)
				}
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			solver := NewNineKwSolver(NineKwConfig{APIKey: "test-key", BaseURL: server.URL})
			balance, err := solver.Balance(context.Background())
			if err != nil {
				t.Fatalf("Balance() error = %v", err)
			}
			if balance != tt.want {
				t.Errorf("Balance() = %f, want %f", balance, tt.want)
			}
		})
	}
}

func TestNineKwSolver_Balance_NotConfigured(t *testing.T) {
	solver := NewNineKwSolver(NineKwConfig{})
	if _, err := solver.Balance(context.Background()); err == nil {
		t.Error("expected error for unconfigured solver")
	}
}

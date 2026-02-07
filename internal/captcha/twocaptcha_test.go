package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func TestTwoCaptchaSolver_Name(t *testing.T) {
	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{})
	if got := solver.Name(); got != "2captcha" {
		t.Errorf("Name() = %q, want %q", got, "2captcha")
	}
}

func TestTwoCaptchaSolver_IsConfigured(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
		want   bool
	}{
		{
			name:   "configured with key",
			apiKey: "test-api-key",
			want:   true,
		},
		{
			name:   "not configured without key",
			apiKey: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solver := NewTwoCaptchaSolver(TwoCaptchaConfig{APIKey: tt.apiKey})
			if got := solver.IsConfigured(); got != tt.want {
				t.Errorf("IsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTwoCaptchaSolver_SolveTurnstile_NotConfigured(t *testing.T) {
	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
	})

	if err == nil {
		t.Error("expected error for unconfigured solver")
	}
}

func TestTwoCaptchaSolver_SolveTurnstile_Success(t *testing.T) {
	// Create test server
	taskID := int64(12345)
	pollCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			json.NewEncoder(w).Encode(twoCaptchaCreateTaskResponse{
				ErrorID: 0,
				TaskID:  taskID,
			})
		case "/getTaskResult":
			pollCount++
			// Return ready on first poll to avoid timeout
			json.NewEncoder(w).Encode(twoCaptchaGetResultResponse{
				ErrorID: 0,
				Status:  "ready",
				Solution: &twoCaptchaTurnstileSolution{
					Token: "test-token-123",
				},
				Cost: "0.002",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 30 * time.Second, // Longer timeout to allow for polling delay
	})

	result, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "0x4AAAAAAA",
		PageURL: "https://example.com",
	})

	if err != nil {
		t.Fatalf("SolveTurnstile() error = %v", err)
	}

	if result.Token != "test-token-123" {
		t.Errorf("Token = %q, want %q", result.Token, "test-token-123")
	}

	if result.Provider != "2captcha" {
		t.Errorf("Provider = %q, want %q", result.Provider, "2captcha")
	}

	if result.Cost != 0.002 {
		t.Errorf("Cost = %f, want %f", result.Cost, 0.002)
	}
}

func TestTwoCaptchaSolver_SolveTurnstile_CreateTaskError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(twoCaptchaCreateTaskResponse{
			ErrorID:          1,
			ErrorCode:        "ERROR_KEY_DOES_NOT_EXIST",
			ErrorDescription: "Account not found",
		})
	}))
	defer server.Close()

	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{
		APIKey:  "invalid-key",
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
	})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
	})

	if err == nil {
		t.Fatal("expected error for invalid API key")
	}

	// Check it's a CaptchaError
	var captchaErr *types.CaptchaError
	if !containsCaptchaError(err, &captchaErr) {
		t.Errorf("expected CaptchaError, got %T", err)
	}
}

func TestTwoCaptchaSolver_SolveTurnstile_ZeroBalance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(twoCaptchaCreateTaskResponse{
			ErrorID:          1,
			ErrorCode:        "ERROR_ZERO_BALANCE",
			ErrorDescription: "Account has zero balance",
		})
	}))
	defer server.Close()

	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
	})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
	})

	if err == nil {
		t.Fatal("expected error for zero balance")
	}

	var captchaErr *types.CaptchaError
	if !containsCaptchaError(err, &captchaErr) {
		t.Errorf("expected CaptchaError, got %T", err)
	}
}

func TestTwoCaptchaSolver_SolveTurnstile_Timeout(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			json.NewEncoder(w).Encode(twoCaptchaCreateTaskResponse{
				ErrorID: 0,
				TaskID:  12345,
			})
		case "/getTaskResult":
			callCount++
			// Always return processing status
			json.NewEncoder(w).Encode(twoCaptchaGetResultResponse{
				ErrorID: 0,
				Status:  "processing",
			})
		}
	}))
	defer server.Close()

	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 1 * time.Second, // Very short timeout
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := solver.SolveTurnstile(ctx, &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
	})

	if err == nil {
		t.Fatal("expected timeout error")
	}

	// Should have received timeout error
	var captchaErr *types.CaptchaError
	if containsCaptchaError(err, &captchaErr) {
		if captchaErr.Code != "timeout" {
			t.Errorf("ErrorCode = %q, want %q", captchaErr.Code, "timeout")
		}
	}
}

func TestTwoCaptchaSolver_Balance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(twoCaptchaBalanceResponse{
			ErrorID: 0,
			Balance: 5.50,
		})
	}))
	defer server.Close()

	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	balance, err := solver.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error = %v", err)
	}

	if balance != 5.50 {
		t.Errorf("Balance() = %f, want %f", balance, 5.50)
	}
}

func TestTwoCaptchaSolver_Balance_NotConfigured(t *testing.T) {
	solver := NewTwoCaptchaSolver(TwoCaptchaConfig{})

	_, err := solver.Balance(context.Background())
	if err == nil {
		t.Error("expected error for unconfigured solver")
	}
}

// containsCaptchaError checks if err contains a CaptchaError
func containsCaptchaError(err error, target **types.CaptchaError) bool {
	for err != nil {
		if ce, ok := err.(*types.CaptchaError); ok {
			*target = ce
			return true
		}
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			err = unwrapper.Unwrap()
		} else {
			break
		}
	}
	return false
}

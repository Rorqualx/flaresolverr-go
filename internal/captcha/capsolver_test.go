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

func TestCapSolverSolver_Name(t *testing.T) {
	solver := NewCapSolverSolver(CapSolverConfig{})
	if got := solver.Name(); got != "capsolver" {
		t.Errorf("Name() = %q, want %q", got, "capsolver")
	}
}

func TestCapSolverSolver_IsConfigured(t *testing.T) {
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
			solver := NewCapSolverSolver(CapSolverConfig{APIKey: tt.apiKey})
			if got := solver.IsConfigured(); got != tt.want {
				t.Errorf("IsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapSolverSolver_SolveTurnstile_NotConfigured(t *testing.T) {
	solver := NewCapSolverSolver(CapSolverConfig{})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
	})

	if err == nil {
		t.Error("expected error for unconfigured solver")
	}
}

func TestCapSolverSolver_SolveTurnstile_Success(t *testing.T) {
	taskID := "task-abc-123"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			json.NewEncoder(w).Encode(capSolverCreateTaskResponse{
				ErrorID: 0,
				TaskID:  taskID,
			})
		case "/getTaskResult":
			json.NewEncoder(w).Encode(capSolverGetResultResponse{
				ErrorID: 0,
				Status:  "ready",
				Solution: &capSolverTurnstileSolution{
					Token: "capsolver-token-456",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	solver := NewCapSolverSolver(CapSolverConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
	})

	result, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "0x4AAAAAAA",
		PageURL: "https://example.com",
	})

	if err != nil {
		t.Fatalf("SolveTurnstile() error = %v", err)
	}

	if result.Token != "capsolver-token-456" {
		t.Errorf("Token = %q, want %q", result.Token, "capsolver-token-456")
	}

	if result.Provider != "capsolver" {
		t.Errorf("Provider = %q, want %q", result.Provider, "capsolver")
	}
}

func TestCapSolverSolver_SolveTurnstile_WithMetadata(t *testing.T) {
	var receivedTask capSolverTurnstileTask
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			var req capSolverCreateTaskRequest
			json.NewDecoder(r.Body).Decode(&req)
			receivedTask = req.Task
			json.NewEncoder(w).Encode(capSolverCreateTaskResponse{
				ErrorID: 0,
				TaskID:  "task-123",
			})
		case "/getTaskResult":
			json.NewEncoder(w).Encode(capSolverGetResultResponse{
				ErrorID: 0,
				Status:  "ready",
				Solution: &capSolverTurnstileSolution{
					Token: "token",
				},
			})
		}
	}))
	defer server.Close()

	solver := NewCapSolverSolver(CapSolverConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
	})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
		Action:  "login",
		CData:   "custom-data",
	})

	if err != nil {
		t.Fatalf("SolveTurnstile() error = %v", err)
	}

	if receivedTask.Metadata == nil {
		t.Fatal("expected metadata to be set")
	}

	if receivedTask.Metadata.Action != "login" {
		t.Errorf("Metadata.Action = %q, want %q", receivedTask.Metadata.Action, "login")
	}

	if receivedTask.Metadata.CData != "custom-data" {
		t.Errorf("Metadata.CData = %q, want %q", receivedTask.Metadata.CData, "custom-data")
	}
}

func TestCapSolverSolver_SolveTurnstile_Failed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/createTask":
			json.NewEncoder(w).Encode(capSolverCreateTaskResponse{
				ErrorID: 0,
				TaskID:  "task-123",
			})
		case "/getTaskResult":
			json.NewEncoder(w).Encode(capSolverGetResultResponse{
				ErrorID: 0,
				Status:  "failed",
			})
		}
	}))
	defer server.Close()

	solver := NewCapSolverSolver(CapSolverConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
	})

	_, err := solver.SolveTurnstile(context.Background(), &TurnstileRequest{
		SiteKey: "test-key",
		PageURL: "https://example.com",
	})

	if err == nil {
		t.Fatal("expected error for failed task")
	}
}

func TestCapSolverSolver_SolveTurnstile_ZeroBalance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(capSolverCreateTaskResponse{
			ErrorID:          1,
			ErrorCode:        "ERROR_ZERO_BALANCE",
			ErrorDescription: "Insufficient balance",
		})
	}))
	defer server.Close()

	solver := NewCapSolverSolver(CapSolverConfig{
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

func TestCapSolverSolver_Balance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(capSolverBalanceResponse{
			ErrorID: 0,
			Balance: 10.25,
		})
	}))
	defer server.Close()

	solver := NewCapSolverSolver(CapSolverConfig{
		APIKey:  "test-key",
		BaseURL: server.URL,
	})

	balance, err := solver.Balance(context.Background())
	if err != nil {
		t.Fatalf("Balance() error = %v", err)
	}

	if balance != 10.25 {
		t.Errorf("Balance() = %f, want %f", balance, 10.25)
	}
}

func TestCapSolverSolver_Balance_NotConfigured(t *testing.T) {
	solver := NewCapSolverSolver(CapSolverConfig{})

	_, err := solver.Balance(context.Background())
	if err == nil {
		t.Error("expected error for unconfigured solver")
	}
}

func TestCapSolverSolver_HandleError(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		description string
		wantErr     error
	}{
		{
			name:    "zero balance",
			code:    "ERROR_ZERO_BALANCE",
			wantErr: types.ErrCaptchaSolverBalance,
		},
		{
			name:    "no workers",
			code:    "ERROR_NO_AVAILABLE_WORKERS",
			wantErr: types.ErrCaptchaSolverRejected,
		},
		{
			name:    "invalid key",
			code:    "ERROR_INVALID_CLIENTKEY",
			wantErr: types.ErrCaptchaSolverRejected,
		},
		{
			name:        "unknown error",
			code:        "UNKNOWN_ERROR",
			description: "Something went wrong",
			wantErr:     types.ErrCaptchaSolverRejected,
		},
	}

	solver := NewCapSolverSolver(CapSolverConfig{APIKey: "test"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := solver.handleError(tt.code, tt.description, "task-123")

			var captchaErr *types.CaptchaError
			if !containsCaptchaError(err, &captchaErr) {
				t.Fatalf("expected CaptchaError, got %T", err)
			}

			if captchaErr.Err != tt.wantErr {
				t.Errorf("Err = %v, want %v", captchaErr.Err, tt.wantErr)
			}
		})
	}
}

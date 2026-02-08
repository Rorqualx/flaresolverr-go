// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	// CapSolver API endpoints
	capSolverBaseURL    = "https://api.capsolver.com"
	capSolverCreateTask = "/createTask"
	capSolverGetResult  = "/getTaskResult"
	capSolverGetBalance = "/getBalance"

	// Default polling interval for CapSolver (faster than 2Captcha)
	capSolverPollInterval = 3 * time.Second

	// CapSolver typically solves faster than 2Captcha
	capSolverDefaultTimeout = 120 * time.Second
)

// CapSolverSolver implements CaptchaSolver for CapSolver API.
type CapSolverSolver struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	timeout    time.Duration
}

// CapSolverConfig contains configuration for CapSolver solver.
type CapSolverConfig struct {
	APIKey  string
	Timeout time.Duration
	BaseURL string // Override for testing
}

// NewCapSolverSolver creates a new CapSolver solver instance.
func NewCapSolverSolver(cfg CapSolverConfig) *CapSolverSolver {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = capSolverDefaultTimeout
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = capSolverBaseURL
	}

	return &CapSolverSolver{
		apiKey:  cfg.APIKey,
		baseURL: baseURL,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout + 10*time.Second, // HTTP timeout slightly longer than solve timeout
		},
	}
}

// Name returns the provider name.
func (s *CapSolverSolver) Name() string {
	return "capsolver"
}

// IsConfigured returns true if API key is set.
func (s *CapSolverSolver) IsConfigured() bool {
	return s.apiKey != ""
}

// capSolverCreateTaskRequest is the request body for createTask.
type capSolverCreateTaskRequest struct {
	ClientKey string                 `json:"clientKey"`
	Task      capSolverTurnstileTask `json:"task"`
}

// capSolverTurnstileTask is the task specification for Turnstile.
type capSolverTurnstileTask struct {
	Type       string             `json:"type"`
	WebsiteURL string             `json:"websiteURL"`
	WebsiteKey string             `json:"websiteKey"`
	Metadata   *capSolverMetadata `json:"metadata,omitempty"`
}

// capSolverMetadata contains optional metadata for Turnstile.
type capSolverMetadata struct {
	Action string `json:"action,omitempty"`
	CData  string `json:"cdata,omitempty"`
}

// capSolverCreateTaskResponse is the response from createTask.
type capSolverCreateTaskResponse struct {
	ErrorID          int    `json:"errorId"`
	ErrorCode        string `json:"errorCode,omitempty"`
	ErrorDescription string `json:"errorDescription,omitempty"`
	TaskID           string `json:"taskId,omitempty"`
}

// capSolverGetResultRequest is the request body for getTaskResult.
type capSolverGetResultRequest struct {
	ClientKey string `json:"clientKey"`
	TaskID    string `json:"taskId"`
}

// capSolverGetResultResponse is the response from getTaskResult.
type capSolverGetResultResponse struct {
	ErrorID          int                         `json:"errorId"`
	ErrorCode        string                      `json:"errorCode,omitempty"`
	ErrorDescription string                      `json:"errorDescription,omitempty"`
	Status           string                      `json:"status"` // "processing", "ready", or "failed"
	Solution         *capSolverTurnstileSolution `json:"solution,omitempty"`
}

// capSolverTurnstileSolution contains the Turnstile solution.
type capSolverTurnstileSolution struct {
	Token string `json:"token"`
}

// capSolverBalanceResponse is the response from getBalance.
type capSolverBalanceResponse struct {
	ErrorID          int     `json:"errorId"`
	ErrorCode        string  `json:"errorCode,omitempty"`
	ErrorDescription string  `json:"errorDescription,omitempty"`
	Balance          float64 `json:"balance"`
}

// SolveTurnstile solves a Turnstile challenge using CapSolver API.
func (s *CapSolverSolver) SolveTurnstile(ctx context.Context, req *TurnstileRequest) (*TurnstileResult, error) {
	if !s.IsConfigured() {
		return nil, fmt.Errorf("capsolver API key not configured")
	}

	startTime := time.Now()

	// Create task
	taskID, err := s.createTask(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	log.Debug().
		Str("task_id", taskID).
		Str("sitekey", req.SiteKey[:min(10, len(req.SiteKey))]+"...").
		Msg("CapSolver task created")

	// Poll for result
	result, err := s.pollResult(ctx, taskID)
	if err != nil {
		return nil, err
	}

	solveTime := time.Since(startTime)

	// CapSolver pricing is ~$2.50 per 1000 solves for Turnstile
	estimatedCost := 0.0025

	return &TurnstileResult{
		Token:     result.Solution.Token,
		SolveTime: solveTime,
		Cost:      estimatedCost,
		Provider:  s.Name(),
	}, nil
}

// createTask creates a new Turnstile solving task.
func (s *CapSolverSolver) createTask(ctx context.Context, req *TurnstileRequest) (string, error) {
	task := capSolverTurnstileTask{
		Type:       "AntiTurnstileTaskProxyLess",
		WebsiteURL: req.PageURL,
		WebsiteKey: req.SiteKey,
	}

	// Add metadata if action or cdata is provided
	if req.Action != "" || req.CData != "" {
		task.Metadata = &capSolverMetadata{
			Action: req.Action,
			CData:  req.CData,
		}
	}

	taskReq := capSolverCreateTaskRequest{
		ClientKey: s.apiKey,
		Task:      task,
	}

	body, err := json.Marshal(taskReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+capSolverCreateTask, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var taskResp capSolverCreateTaskResponse
	if err := json.Unmarshal(respBody, &taskResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if taskResp.ErrorID != 0 {
		return "", s.handleError(taskResp.ErrorCode, taskResp.ErrorDescription, "")
	}

	return taskResp.TaskID, nil
}

// pollResult polls for the task result until complete or timeout.
func (s *CapSolverSolver) pollResult(ctx context.Context, taskID string) (*capSolverGetResultResponse, error) {
	// Create a timeout context for polling
	pollCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	ticker := time.NewTicker(capSolverPollInterval)
	defer ticker.Stop()

	// Initial delay before first poll
	select {
	case <-pollCtx.Done():
		return nil, types.NewCaptchaTimeoutError(s.Name(), taskID)
	case <-ticker.C:
	}

	for {
		select {
		case <-pollCtx.Done():
			return nil, types.NewCaptchaTimeoutError(s.Name(), taskID)
		case <-ticker.C:
			result, err := s.getResult(pollCtx, taskID)
			if err != nil {
				return nil, err
			}

			switch result.Status {
			case "ready":
				if result.Solution == nil || result.Solution.Token == "" {
					return nil, fmt.Errorf("received ready status but no token")
				}
				return result, nil
			case "failed":
				return nil, types.NewCaptchaRejectedError(s.Name(), "failed", "task failed")
			default:
				log.Debug().
					Str("task_id", taskID).
					Str("status", result.Status).
					Msg("CapSolver task still processing")
			}
		}
	}
}

// getResult retrieves the result for a task.
func (s *CapSolverSolver) getResult(ctx context.Context, taskID string) (*capSolverGetResultResponse, error) {
	resultReq := capSolverGetResultRequest{
		ClientKey: s.apiKey,
		TaskID:    taskID,
	}

	body, err := json.Marshal(resultReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+capSolverGetResult, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var resultResp capSolverGetResultResponse
	if err := json.Unmarshal(respBody, &resultResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if resultResp.ErrorID != 0 {
		return nil, s.handleError(resultResp.ErrorCode, resultResp.ErrorDescription, taskID)
	}

	return &resultResp, nil
}

// Balance retrieves the current account balance.
func (s *CapSolverSolver) Balance(ctx context.Context) (float64, error) {
	if !s.IsConfigured() {
		return 0, fmt.Errorf("capsolver API key not configured")
	}

	reqBody := map[string]string{"clientKey": s.apiKey}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+capSolverGetBalance, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	var balanceResp capSolverBalanceResponse
	if err := json.Unmarshal(respBody, &balanceResp); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}

	if balanceResp.ErrorID != 0 {
		return 0, s.handleError(balanceResp.ErrorCode, balanceResp.ErrorDescription, "")
	}

	return balanceResp.Balance, nil
}

// handleError converts CapSolver error codes to appropriate error types.
func (s *CapSolverSolver) handleError(code, description, taskID string) error {
	switch code {
	case "ERROR_ZERO_BALANCE":
		return types.NewCaptchaBalanceError(s.Name())
	case "ERROR_NO_AVAILABLE_WORKERS":
		return types.NewCaptchaRejectedError(s.Name(), code, "no workers available, try again later")
	case "ERROR_INVALID_TASK_DATA", "ERROR_WRONG_WEBSITEKEY":
		return types.NewCaptchaRejectedError(s.Name(), code, "invalid sitekey or task data")
	case "ERROR_CAPTCHA_UNSOLVABLE":
		return types.NewCaptchaRejectedError(s.Name(), code, "captcha could not be solved")
	case "ERROR_KEY_DENIED", "ERROR_INVALID_CLIENTKEY":
		return types.NewCaptchaRejectedError(s.Name(), code, "invalid API key")
	case "ERROR_TASK_NOT_FOUND":
		return types.NewCaptchaRejectedError(s.Name(), code, "task not found or expired")
	default:
		msg := description
		if msg == "" {
			msg = code
		}
		return &types.CaptchaError{
			Provider: s.Name(),
			TaskID:   taskID,
			Code:     code,
			Message:  fmt.Sprintf("CapSolver error: %s", msg),
			Err:      types.ErrCaptchaSolverRejected,
		}
	}
}

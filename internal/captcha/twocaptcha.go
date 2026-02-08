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
	// 2Captcha API endpoints
	twoCaptchaBaseURL    = "https://api.2captcha.com"
	twoCaptchaCreateTask = "/createTask"
	twoCaptchaGetResult  = "/getTaskResult"
	twoCaptchaGetBalance = "/getBalance"

	// Default polling interval for 2Captcha
	twoCaptchaPollInterval = 5 * time.Second

	// 2Captcha typically solves Turnstile in 10-30 seconds
	twoCaptchaDefaultTimeout = 120 * time.Second
)

// TwoCaptchaSolver implements CaptchaSolver for 2Captcha API.
type TwoCaptchaSolver struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string
	timeout    time.Duration
}

// TwoCaptchaConfig contains configuration for 2Captcha solver.
type TwoCaptchaConfig struct {
	APIKey  string
	Timeout time.Duration
	BaseURL string // Override for testing
}

// NewTwoCaptchaSolver creates a new 2Captcha solver instance.
func NewTwoCaptchaSolver(cfg TwoCaptchaConfig) *TwoCaptchaSolver {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = twoCaptchaDefaultTimeout
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = twoCaptchaBaseURL
	}

	return &TwoCaptchaSolver{
		apiKey:  cfg.APIKey,
		baseURL: baseURL,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout + 10*time.Second, // HTTP timeout slightly longer than solve timeout
		},
	}
}

// Name returns the provider name.
func (s *TwoCaptchaSolver) Name() string {
	return "2captcha"
}

// IsConfigured returns true if API key is set.
func (s *TwoCaptchaSolver) IsConfigured() bool {
	return s.apiKey != ""
}

// twoCaptchaCreateTaskRequest is the request body for createTask.
type twoCaptchaCreateTaskRequest struct {
	ClientKey string                 `json:"clientKey"`
	Task      twoCaptchaTurnstileTask `json:"task"`
}

// twoCaptchaTurnstileTask is the task specification for Turnstile.
type twoCaptchaTurnstileTask struct {
	Type       string `json:"type"`
	WebsiteURL string `json:"websiteURL"`
	WebsiteKey string `json:"websiteKey"`
	Action     string `json:"action,omitempty"`
	Data       string `json:"data,omitempty"`
}

// twoCaptchaCreateTaskResponse is the response from createTask.
type twoCaptchaCreateTaskResponse struct {
	ErrorID          int    `json:"errorId"`
	ErrorCode        string `json:"errorCode,omitempty"`
	ErrorDescription string `json:"errorDescription,omitempty"`
	TaskID           int64  `json:"taskId,omitempty"`
}

// twoCaptchaGetResultRequest is the request body for getTaskResult.
type twoCaptchaGetResultRequest struct {
	ClientKey string `json:"clientKey"`
	TaskID    int64  `json:"taskId"`
}

// twoCaptchaGetResultResponse is the response from getTaskResult.
type twoCaptchaGetResultResponse struct {
	ErrorID          int                        `json:"errorId"`
	ErrorCode        string                     `json:"errorCode,omitempty"`
	ErrorDescription string                     `json:"errorDescription,omitempty"`
	Status           string                     `json:"status"` // "processing" or "ready"
	Solution         *twoCaptchaTurnstileSolution `json:"solution,omitempty"`
	Cost             string                     `json:"cost,omitempty"`
}

// twoCaptchaTurnstileSolution contains the Turnstile solution.
type twoCaptchaTurnstileSolution struct {
	Token string `json:"token"`
}

// twoCaptchaBalanceResponse is the response from getBalance.
type twoCaptchaBalanceResponse struct {
	ErrorID          int     `json:"errorId"`
	ErrorCode        string  `json:"errorCode,omitempty"`
	ErrorDescription string  `json:"errorDescription,omitempty"`
	Balance          float64 `json:"balance"`
}

// SolveTurnstile solves a Turnstile challenge using 2Captcha API.
func (s *TwoCaptchaSolver) SolveTurnstile(ctx context.Context, req *TurnstileRequest) (*TurnstileResult, error) {
	if !s.IsConfigured() {
		return nil, fmt.Errorf("2captcha API key not configured")
	}

	startTime := time.Now()

	// Create task
	taskID, err := s.createTask(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	log.Debug().
		Int64("task_id", taskID).
		Str("sitekey", req.SiteKey[:min(10, len(req.SiteKey))]+"...").
		Msg("2Captcha task created")

	// Poll for result
	result, err := s.pollResult(ctx, taskID)
	if err != nil {
		return nil, err
	}

	solveTime := time.Since(startTime)

	// Parse cost (2Captcha returns cost as string)
	var cost float64
	if result.Cost != "" {
		_, _ = fmt.Sscanf(result.Cost, "%f", &cost)
	}

	return &TurnstileResult{
		Token:     result.Solution.Token,
		SolveTime: solveTime,
		Cost:      cost,
		Provider:  s.Name(),
	}, nil
}

// createTask creates a new Turnstile solving task.
func (s *TwoCaptchaSolver) createTask(ctx context.Context, req *TurnstileRequest) (int64, error) {
	taskReq := twoCaptchaCreateTaskRequest{
		ClientKey: s.apiKey,
		Task: twoCaptchaTurnstileTask{
			Type:       "TurnstileTaskProxyless",
			WebsiteURL: req.PageURL,
			WebsiteKey: req.SiteKey,
			Action:     req.Action,
			Data:       req.CData,
		},
	}

	body, err := json.Marshal(taskReq)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+twoCaptchaCreateTask, bytes.NewReader(body))
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

	var taskResp twoCaptchaCreateTaskResponse
	if err := json.Unmarshal(respBody, &taskResp); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}

	if taskResp.ErrorID != 0 {
		return 0, s.handleError(taskResp.ErrorCode, taskResp.ErrorDescription, "")
	}

	return taskResp.TaskID, nil
}

// pollResult polls for the task result until complete or timeout.
func (s *TwoCaptchaSolver) pollResult(ctx context.Context, taskID int64) (*twoCaptchaGetResultResponse, error) {
	// Create a timeout context for polling
	pollCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	ticker := time.NewTicker(twoCaptchaPollInterval)
	defer ticker.Stop()

	// Initial delay before first poll (2Captcha recommends 5s)
	select {
	case <-pollCtx.Done():
		return nil, types.NewCaptchaTimeoutError(s.Name(), fmt.Sprintf("%d", taskID))
	case <-ticker.C:
	}

	for {
		select {
		case <-pollCtx.Done():
			return nil, types.NewCaptchaTimeoutError(s.Name(), fmt.Sprintf("%d", taskID))
		case <-ticker.C:
			result, err := s.getResult(pollCtx, taskID)
			if err != nil {
				return nil, err
			}

			if result.Status == "ready" {
				if result.Solution == nil || result.Solution.Token == "" {
					return nil, fmt.Errorf("received ready status but no token")
				}
				return result, nil
			}

			log.Debug().
				Int64("task_id", taskID).
				Str("status", result.Status).
				Msg("2Captcha task still processing")
		}
	}
}

// getResult retrieves the result for a task.
func (s *TwoCaptchaSolver) getResult(ctx context.Context, taskID int64) (*twoCaptchaGetResultResponse, error) {
	resultReq := twoCaptchaGetResultRequest{
		ClientKey: s.apiKey,
		TaskID:    taskID,
	}

	body, err := json.Marshal(resultReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+twoCaptchaGetResult, bytes.NewReader(body))
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

	var resultResp twoCaptchaGetResultResponse
	if err := json.Unmarshal(respBody, &resultResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if resultResp.ErrorID != 0 {
		return nil, s.handleError(resultResp.ErrorCode, resultResp.ErrorDescription, fmt.Sprintf("%d", taskID))
	}

	return &resultResp, nil
}

// Balance retrieves the current account balance.
func (s *TwoCaptchaSolver) Balance(ctx context.Context) (float64, error) {
	if !s.IsConfigured() {
		return 0, fmt.Errorf("2captcha API key not configured")
	}

	reqBody := map[string]string{"clientKey": s.apiKey}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+twoCaptchaGetBalance, bytes.NewReader(body))
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

	var balanceResp twoCaptchaBalanceResponse
	if err := json.Unmarshal(respBody, &balanceResp); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}

	if balanceResp.ErrorID != 0 {
		return 0, s.handleError(balanceResp.ErrorCode, balanceResp.ErrorDescription, "")
	}

	return balanceResp.Balance, nil
}

// handleError converts 2Captcha error codes to appropriate error types.
func (s *TwoCaptchaSolver) handleError(code, description, taskID string) error {
	switch code {
	case "ERROR_ZERO_BALANCE":
		return types.NewCaptchaBalanceError(s.Name())
	case "ERROR_NO_SLOT_AVAILABLE":
		return types.NewCaptchaRejectedError(s.Name(), code, "no workers available, try again later")
	case "ERROR_WRONG_GOOGLEKEY", "ERROR_WRONG_SITEKEY":
		return types.NewCaptchaRejectedError(s.Name(), code, "invalid sitekey")
	case "ERROR_CAPTCHA_UNSOLVABLE":
		return types.NewCaptchaRejectedError(s.Name(), code, "captcha could not be solved")
	case "ERROR_BAD_DUPLICATES":
		return types.NewCaptchaRejectedError(s.Name(), code, "too many duplicate requests")
	case "ERROR_KEY_DOES_NOT_EXIST", "ERROR_WRONG_USER_KEY":
		return types.NewCaptchaRejectedError(s.Name(), code, "invalid API key")
	default:
		msg := description
		if msg == "" {
			msg = code
		}
		return &types.CaptchaError{
			Provider: s.Name(),
			TaskID:   taskID,
			Code:     code,
			Message:  fmt.Sprintf("2Captcha error: %s", msg),
			Err:      types.ErrCaptchaSolverRejected,
		}
	}
}

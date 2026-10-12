// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"context"
	"fmt"
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

	capSolverName = "capsolver"

	// CapSolver does not report a per-task cost; these are its list prices.
	capSolverTurnstileCost = 0.0025
	capSolverHCaptchaCost  = 0.003
)

// CapSolverSolver implements CaptchaSolver for CapSolver API.
type CapSolverSolver struct {
	apiKey       string
	httpClient   *http.Client
	baseURL      string
	timeout      time.Duration
	pollInterval time.Duration
}

func init() {
	Register(capSolverName, func(opts ProviderOptions) CaptchaSolver {
		return NewCapSolverSolver(CapSolverConfig(opts))
	})
}

// CapSolverConfig contains configuration for CapSolver solver.
type CapSolverConfig struct {
	APIKey       string
	Timeout      time.Duration
	BaseURL      string        // Override for testing and self-hosted gateways
	PollInterval time.Duration // Override for testing (default: capSolverPollInterval)
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

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = capSolverPollInterval
	}

	return &CapSolverSolver{
		apiKey:       cfg.APIKey,
		baseURL:      baseURL,
		timeout:      timeout,
		pollInterval: pollInterval,
		httpClient: &http.Client{
			Timeout: timeout + 10*time.Second, // HTTP timeout slightly longer than solve timeout
		},
	}
}

// Name returns the provider name.
func (s *CapSolverSolver) Name() string {
	return capSolverName
}

// IsConfigured returns true if API key is set.
func (s *CapSolverSolver) IsConfigured() bool {
	return s.apiKey != ""
}

// capSolverCreateTaskRequest is the request body for createTask.
type capSolverCreateTaskRequest struct {
	ClientKey string        `json:"clientKey"`
	Task      capSolverTask `json:"task"`
}

// capSolverTask is the task specification.
type capSolverTask struct {
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

// capSolverTaskResponse is the response from createTask and getTaskResult.
// createTask normally answers with status "idle" and a task id, but may answer
// "ready" with the solution for task kinds it solves synchronously.
type capSolverTaskResponse struct {
	ErrorID          int       `json:"errorId"`
	ErrorCode        string    `json:"errorCode,omitempty"` // null on success
	ErrorDescription string    `json:"errorDescription,omitempty"`
	TaskID           string    `json:"taskId,omitempty"`
	Status           string    `json:"status"` // "idle", "processing", "ready"; "failed" seen in the wild
	Solution         *solution `json:"solution,omitempty"`
}

// capSolverGetResultRequest is the request body for getTaskResult.
type capSolverGetResultRequest struct {
	ClientKey string `json:"clientKey"`
	TaskID    string `json:"taskId"`
}

// capSolverBalanceResponse is the response from getBalance.
type capSolverBalanceResponse struct {
	ErrorID          int     `json:"errorId"`
	ErrorCode        string  `json:"errorCode,omitempty"`
	ErrorDescription string  `json:"errorDescription,omitempty"`
	Balance          float64 `json:"balance"`
}

// SolveTurnstile solves a standalone Turnstile widget using CapSolver.
//
// It refuses a Cloudflare managed challenge before making any request.
// AntiTurnstileTaskProxyLess has no field for the challenge page's
// chlPageData, so CapSolver would return (and bill for) a token the
// interstitial cannot accept. CapSolver's challenge-page product is a different
// task that needs a sticky proxy matching the browser's egress.
func (s *CapSolverSolver) SolveTurnstile(ctx context.Context, req *TurnstileRequest) (*TurnstileResult, error) {
	if req.PageData != "" {
		return nil, notCreated(types.NewCaptchaRejectedError(capSolverName, "UNSUPPORTED",
			"CapSolver cannot solve a Cloudflare managed challenge with a proxyless Turnstile task"))
	}

	task := capSolverTask{
		Type:       "AntiTurnstileTaskProxyLess",
		WebsiteURL: req.PageURL,
		WebsiteKey: req.SiteKey,
	}
	if req.Action != "" || req.CData != "" {
		task.Metadata = &capSolverMetadata{Action: req.Action, CData: req.CData}
	}

	log.Debug().Str("sitekey", sitekeyPreview(req.SiteKey)).Msg("Creating CapSolver Turnstile task")
	return s.solve(ctx, task, capSolverTurnstileCost)
}

// SolveHCaptcha solves an hCaptcha challenge using the CapSolver API.
func (s *CapSolverSolver) SolveHCaptcha(ctx context.Context, req *HCaptchaRequest) (*CaptchaResult, error) {
	log.Debug().Str("sitekey", sitekeyPreview(req.SiteKey)).Msg("Creating CapSolver hCaptcha task")
	return s.solve(ctx, capSolverTask{
		Type:       "HCaptchaTaskProxyLess",
		WebsiteURL: req.PageURL,
		WebsiteKey: req.SiteKey,
	}, capSolverHCaptchaCost)
}

// solve creates the task and waits for its solution.
func (s *CapSolverSolver) solve(ctx context.Context, task capSolverTask, cost float64) (*TurnstileResult, error) {
	if !s.IsConfigured() {
		return nil, notCreated(fmt.Errorf("%s API key not configured", capSolverName))
	}

	startTime := time.Now()

	created, err := s.createTask(ctx, task)
	if err != nil {
		return nil, err
	}
	log.Debug().Str("task_id", created.TaskID).Msg("CapSolver task created")

	result := created
	if created.Status != "ready" || created.Solution.value() == "" {
		result, err = pollTask(ctx, pollConfig{
			provider: capSolverName,
			taskID:   created.TaskID,
			timeout:  s.timeout,
			interval: s.pollInterval,
		}, func(pollCtx context.Context) (*capSolverTaskResponse, bool, error) {
			return s.getResult(pollCtx, created.TaskID)
		})
		if err != nil {
			return nil, err
		}
	}

	return &TurnstileResult{
		Token:     result.Solution.value(),
		UserAgent: result.Solution.agent(),
		SolveTime: time.Since(startTime),
		Cost:      cost,
		Provider:  capSolverName,
	}, nil
}

// createTask submits a task. A definitive refusal by the provider is returned
// as a "not created" error; a failure that leaves it unknown whether the task
// was accepted is not.
func (s *CapSolverSolver) createTask(ctx context.Context, task capSolverTask) (*capSolverTaskResponse, error) {
	var resp capSolverTaskResponse
	err := doJSON(ctx, s.httpClient, http.MethodPost, s.baseURL+capSolverCreateTask,
		capSolverCreateTaskRequest{ClientKey: s.apiKey, Task: task}, &resp)
	if err != nil {
		return nil, createFailure(fmt.Errorf("%s: failed to create task: %w", capSolverName, err))
	}
	if resp.ErrorID != 0 {
		return nil, notCreated(s.handleError(resp.ErrorCode, resp.ErrorDescription, ""))
	}
	if resp.TaskID == "" {
		return nil, notCreated(fmt.Errorf("%s: createTask returned no task id", capSolverName))
	}
	return &resp, nil
}

// getResult performs one result poll. ready is false (with a nil error) while
// the task is idle or processing; any status other than "ready" and "failed"
// keeps polling until the deadline.
func (s *CapSolverSolver) getResult(ctx context.Context, taskID string) (*capSolverTaskResponse, bool, error) {
	var resp capSolverTaskResponse
	err := doJSON(ctx, s.httpClient, http.MethodPost, s.baseURL+capSolverGetResult,
		capSolverGetResultRequest{ClientKey: s.apiKey, TaskID: taskID}, &resp)
	if err != nil {
		return nil, false, err
	}
	if resp.ErrorID != 0 {
		return nil, false, s.handleError(resp.ErrorCode, resp.ErrorDescription, taskID)
	}

	switch resp.Status {
	case "ready":
		if resp.Solution.value() == "" {
			return nil, false, types.NewCaptchaRejectedError(capSolverName, "EMPTY_SOLUTION", "task reported ready without a token")
		}
		return &resp, true, nil
	case "failed":
		return nil, false, types.NewCaptchaRejectedError(capSolverName, "failed", "task failed")
	default:
		return nil, false, nil
	}
}

// Balance retrieves the current account balance.
func (s *CapSolverSolver) Balance(ctx context.Context) (float64, error) {
	if !s.IsConfigured() {
		return 0, fmt.Errorf("%s API key not configured", capSolverName)
	}

	var resp capSolverBalanceResponse
	err := doJSON(ctx, s.httpClient, http.MethodPost, s.baseURL+capSolverGetBalance,
		map[string]string{"clientKey": s.apiKey}, &resp)
	if err != nil {
		return 0, fmt.Errorf("%s: failed to get balance: %w", capSolverName, err)
	}
	if resp.ErrorID != 0 {
		return 0, s.handleError(resp.ErrorCode, resp.ErrorDescription, "")
	}
	return resp.Balance, nil
}

// handleError converts CapSolver error codes to appropriate error types.
func (s *CapSolverSolver) handleError(code, description, taskID string) error {
	switch code {
	case "ERROR_ZERO_BALANCE":
		return types.NewCaptchaBalanceError(capSolverName)
	case "ERROR_NO_AVAILABLE_WORKERS":
		return types.NewCaptchaRejectedError(capSolverName, code, "no workers available, try again later")
	case "ERROR_INVALID_TASK_DATA", "ERROR_WRONG_WEBSITEKEY":
		return types.NewCaptchaRejectedError(capSolverName, code, "invalid sitekey or task data")
	case "ERROR_CAPTCHA_UNSOLVABLE":
		return types.NewCaptchaRejectedError(capSolverName, code, "captcha could not be solved")
	case "ERROR_KEY_DENIED", "ERROR_INVALID_CLIENTKEY":
		return types.NewCaptchaRejectedError(capSolverName, code, "invalid API key")
	case "ERROR_TASK_NOT_FOUND":
		return types.NewCaptchaRejectedError(capSolverName, code, "task not found or expired")
	case "ERROR_TASK_NOT_SUPPORTED":
		return types.NewCaptchaRejectedError(capSolverName, code, "task type not supported by this provider")
	default:
		return &types.CaptchaError{
			Provider: capSolverName,
			TaskID:   taskID,
			Code:     code,
			Message:  fmt.Sprintf("CapSolver error: %s", providerMessage(description, code, s.apiKey)),
			Err:      types.ErrCaptchaSolverRejected,
		}
	}
}

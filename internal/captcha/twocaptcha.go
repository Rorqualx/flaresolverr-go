// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
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

	// Default polling interval for 2Captcha (its docs ask for at least 5s)
	twoCaptchaPollInterval = 5 * time.Second

	// 2Captcha typically solves Turnstile in 10-30 seconds
	twoCaptchaDefaultTimeout = 120 * time.Second

	twoCaptchaName = "2captcha"
)

// taskDialect selects the field names a createTask-compatible provider expects
// for the Cloudflare challenge-page parameters. The APIs are otherwise the same.
type taskDialect int

const (
	// dialectTwoCaptcha: action / data / pagedata
	dialectTwoCaptcha taskDialect = iota
	// dialectAntiCaptcha: action / cData / chlPageData
	dialectAntiCaptcha
)

// TwoCaptchaSolver implements CaptchaSolver for the 2Captcha API, and for the
// providers that speak the same createTask/getTaskResult protocol.
type TwoCaptchaSolver struct {
	name         string // provider name reported in results, errors and logs
	dialect      taskDialect
	apiKey       string
	httpClient   *http.Client
	baseURL      string
	timeout      time.Duration
	pollInterval time.Duration
}

func init() {
	Register(twoCaptchaName, func(opts ProviderOptions) CaptchaSolver {
		return NewTwoCaptchaSolver(TwoCaptchaConfig(opts))
	})
}

// TwoCaptchaConfig contains configuration for 2Captcha solver.
type TwoCaptchaConfig struct {
	APIKey       string
	Timeout      time.Duration
	BaseURL      string        // Override for testing and self-hosted gateways
	PollInterval time.Duration // Override for testing (default: twoCaptchaPollInterval)
}

// NewTwoCaptchaSolver creates a new 2Captcha solver instance.
func NewTwoCaptchaSolver(cfg TwoCaptchaConfig) *TwoCaptchaSolver {
	return newCreateTaskSolver(twoCaptchaName, dialectTwoCaptcha, twoCaptchaBaseURL, cfg)
}

// newCreateTaskSolver builds a solver for a 2Captcha-protocol provider.
func newCreateTaskSolver(name string, dialect taskDialect, defaultBaseURL string, cfg TwoCaptchaConfig) *TwoCaptchaSolver {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = twoCaptchaDefaultTimeout
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = twoCaptchaPollInterval
	}

	return &TwoCaptchaSolver{
		name:         name,
		dialect:      dialect,
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
func (s *TwoCaptchaSolver) Name() string {
	return s.name
}

// IsConfigured returns true if API key is set.
func (s *TwoCaptchaSolver) IsConfigured() bool {
	return s.apiKey != ""
}

// twoCaptchaCreateTaskRequest is the request body for createTask.
type twoCaptchaCreateTaskRequest struct {
	ClientKey string                 `json:"clientKey"`
	Task      map[string]interface{} `json:"task"`
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
	ErrorID          int        `json:"errorId"`
	ErrorCode        string     `json:"errorCode,omitempty"`
	ErrorDescription string     `json:"errorDescription,omitempty"`
	Status           string     `json:"status"` // "processing" or "ready"
	Solution         *solution  `json:"solution,omitempty"`
	Cost             flexString `json:"cost,omitempty"` // sent as a string, sometimes a number
}

// twoCaptchaBalanceResponse is the response from getBalance.
type twoCaptchaBalanceResponse struct {
	ErrorID          int     `json:"errorId"`
	ErrorCode        string  `json:"errorCode,omitempty"`
	ErrorDescription string  `json:"errorDescription,omitempty"`
	Balance          float64 `json:"balance"`
}

// SolveTurnstile solves a Turnstile challenge.
func (s *TwoCaptchaSolver) SolveTurnstile(ctx context.Context, req *TurnstileRequest) (*TurnstileResult, error) {
	log.Debug().
		Str("provider", s.name).
		Str("sitekey", sitekeyPreview(req.SiteKey)).
		Bool("managed", req.PageData != "").
		Msg("Creating Turnstile task")
	return s.solve(ctx, s.turnstileTask(req))
}

// SolveHCaptcha solves an hCaptcha challenge.
func (s *TwoCaptchaSolver) SolveHCaptcha(ctx context.Context, req *HCaptchaRequest) (*CaptchaResult, error) {
	log.Debug().
		Str("provider", s.name).
		Str("sitekey", sitekeyPreview(req.SiteKey)).
		Msg("Creating hCaptcha task")
	return s.solve(ctx, map[string]interface{}{
		"type":       "HCaptchaTaskProxyless",
		"websiteURL": req.PageURL,
		"websiteKey": req.SiteKey,
	})
}

// turnstileTask builds the Turnstile task in this provider's dialect. For
// Cloudflare challenge pages the action, cData and chlPageData captured from
// the turnstile.render() call are all required (see intercept.go).
func (s *TwoCaptchaSolver) turnstileTask(req *TurnstileRequest) map[string]interface{} {
	task := map[string]interface{}{
		"type":       "TurnstileTaskProxyless",
		"websiteURL": req.PageURL,
		"websiteKey": req.SiteKey,
	}
	set := func(key, value string) {
		if value != "" {
			task[key] = value
		}
	}

	set("action", req.Action)
	switch s.dialect {
	case dialectAntiCaptcha:
		set("cData", req.CData)
		set("chlPageData", req.PageData)
		// anti-captcha: "providing your own custom User-Agent ... won't work at all"
	default:
		set("data", req.CData)
		set("pagedata", req.PageData)
		set("userAgent", req.UserAgent)
	}
	return task
}

// solve creates the task and waits for its solution.
func (s *TwoCaptchaSolver) solve(ctx context.Context, task map[string]interface{}) (*TurnstileResult, error) {
	if !s.IsConfigured() {
		return nil, notCreated(fmt.Errorf("%s API key not configured", s.name))
	}

	startTime := time.Now()

	taskID, err := s.createTask(ctx, task)
	if err != nil {
		return nil, err
	}
	taskLabel := strconv.FormatInt(taskID, 10)
	log.Debug().Str("provider", s.name).Str("task_id", taskLabel).Msg("Captcha task created")

	result, err := pollTask(ctx, pollConfig{
		provider: s.name,
		taskID:   taskLabel,
		timeout:  s.timeout,
		interval: s.pollInterval,
	}, func(pollCtx context.Context) (*twoCaptchaGetResultResponse, bool, error) {
		return s.getResult(pollCtx, taskID)
	})
	if err != nil {
		return nil, err
	}

	return &TurnstileResult{
		Token:     result.Solution.value(),
		UserAgent: result.Solution.agent(),
		SolveTime: time.Since(startTime),
		Cost:      result.Cost.float(),
		Provider:  s.name,
	}, nil
}

// createTask submits a task. A definitive refusal by the provider is returned
// as a "not created" error; a failure that leaves it unknown whether the task
// was accepted (a dropped connection, a gateway error) is not.
func (s *TwoCaptchaSolver) createTask(ctx context.Context, task map[string]interface{}) (int64, error) {
	var resp twoCaptchaCreateTaskResponse
	err := doJSON(ctx, s.httpClient, http.MethodPost, s.baseURL+twoCaptchaCreateTask,
		twoCaptchaCreateTaskRequest{ClientKey: s.apiKey, Task: task}, &resp)
	if err != nil {
		return 0, createFailure(fmt.Errorf("%s: failed to create task: %w", s.name, err))
	}
	if resp.ErrorID != 0 {
		return 0, notCreated(s.handleError(resp.ErrorCode, resp.ErrorDescription, ""))
	}
	if resp.TaskID == 0 {
		return 0, notCreated(fmt.Errorf("%s: createTask returned no task id", s.name))
	}
	return resp.TaskID, nil
}

// getResult performs one result poll. ready is false (with a nil error) while
// the task is still being worked on.
func (s *TwoCaptchaSolver) getResult(ctx context.Context, taskID int64) (*twoCaptchaGetResultResponse, bool, error) {
	var resp twoCaptchaGetResultResponse
	err := doJSON(ctx, s.httpClient, http.MethodPost, s.baseURL+twoCaptchaGetResult,
		twoCaptchaGetResultRequest{ClientKey: s.apiKey, TaskID: taskID}, &resp)
	if err != nil {
		return nil, false, err
	}
	if resp.ErrorID != 0 {
		return nil, false, s.handleError(resp.ErrorCode, resp.ErrorDescription, strconv.FormatInt(taskID, 10))
	}
	if resp.Status != "ready" {
		return nil, false, nil
	}
	if resp.Solution.value() == "" {
		return nil, false, types.NewCaptchaRejectedError(s.name, "EMPTY_SOLUTION", "task reported ready without a token")
	}
	return &resp, true, nil
}

// Balance retrieves the current account balance.
func (s *TwoCaptchaSolver) Balance(ctx context.Context) (float64, error) {
	if !s.IsConfigured() {
		return 0, fmt.Errorf("%s API key not configured", s.name)
	}

	var resp twoCaptchaBalanceResponse
	err := doJSON(ctx, s.httpClient, http.MethodPost, s.baseURL+twoCaptchaGetBalance,
		map[string]string{"clientKey": s.apiKey}, &resp)
	if err != nil {
		return 0, fmt.Errorf("%s: failed to get balance: %w", s.name, err)
	}
	if resp.ErrorID != 0 {
		return 0, s.handleError(resp.ErrorCode, resp.ErrorDescription, "")
	}
	return resp.Balance, nil
}

// handleError converts provider error codes to appropriate error types.
func (s *TwoCaptchaSolver) handleError(code, description, taskID string) error {
	switch code {
	case "ERROR_ZERO_BALANCE":
		return types.NewCaptchaBalanceError(s.name)
	case "ERROR_NO_SLOT_AVAILABLE":
		return types.NewCaptchaRejectedError(s.name, code, "no workers available, try again later")
	case "ERROR_WRONG_GOOGLEKEY", "ERROR_WRONG_SITEKEY":
		return types.NewCaptchaRejectedError(s.name, code, "invalid sitekey")
	case "ERROR_CAPTCHA_UNSOLVABLE":
		return types.NewCaptchaRejectedError(s.name, code, "captcha could not be solved")
	case "ERROR_BAD_DUPLICATES":
		return types.NewCaptchaRejectedError(s.name, code, "too many duplicate requests")
	case "ERROR_KEY_DOES_NOT_EXIST", "ERROR_WRONG_USER_KEY":
		return types.NewCaptchaRejectedError(s.name, code, "invalid API key")
	case "ERROR_TASK_NOT_SUPPORTED", "ERROR_TASK_ABSENT":
		return types.NewCaptchaRejectedError(s.name, code, "task type not supported by this provider")
	default:
		return &types.CaptchaError{
			Provider: s.name,
			TaskID:   taskID,
			Code:     code,
			Message:  fmt.Sprintf("%s error: %s", s.name, providerMessage(description, code, s.apiKey)),
			Err:      types.ErrCaptchaSolverRejected,
		}
	}
}

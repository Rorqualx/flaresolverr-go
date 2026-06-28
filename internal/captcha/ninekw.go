// Package captcha provides external CAPTCHA solver integration.
//
// ninekw.go implements the 9kw.eu provider (https://www.9kw.eu). 9kw is a
// human-powered solving pool with a free credit tier (credits are earned by
// solving captchas for others, or bought). Unlike 2Captcha/CapSolver/anti-captcha
// — which use a JSON createTask/getTaskResult API — 9kw exposes a single CGI
// endpoint driven by GET query parameters.
//
// SCOPE / KNOWN LIMITATION — 9kw does NOT support Cloudflare Turnstile. Its
// interactive captcha types are image, reCAPTCHA v2/v3, FunCaptcha, hCaptcha,
// keycaptcha, geetest and cutcaptcha (verified against the 9kw API docs and the
// OpenBullet CaptchaSharp NineKwService reference implementation — neither has a
// Turnstile path). So SolveTurnstile returns a typed "unsupported" error, which
// makes SolverChain fall through to a Turnstile-capable provider. hCaptcha is
// fully supported via oldsource=hcaptcha. This means 9kw does NOT help the
// Cloudflare managed-challenge / Turnstile path that drives issues #11/#13; it
// adds hCaptcha (and, in future, reCAPTCHA) solving capability.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	// 9kw exposes one CGI endpoint; all actions are GET query parameters.
	nineKwBaseURL = "https://www.9kw.eu/index.cgi"

	// Action names.
	nineKwActionUpload  = "usercaptchaupload"
	nineKwActionResult  = "usercaptchacorrectdata"
	nineKwActionBalance = "usercaptchaguthaben"

	// oldsource identifiers for interactive (token) captchas.
	nineKwSourceHCaptcha = "hcaptcha"

	// Human solving is slow; poll less aggressively than the automated providers.
	nineKwPollInterval = 10 * time.Second

	// Default solve budget when none is supplied.
	nineKwDefaultTimeout = 180 * time.Second
)

// NineKwSolver implements CaptchaSolver for the 9kw.eu API.
type NineKwSolver struct {
	apiKey       string
	httpClient   *http.Client
	baseURL      string
	timeout      time.Duration
	pollInterval time.Duration
}

func init() {
	Register("9kw", func(apiKey string, timeout time.Duration) CaptchaSolver {
		return NewNineKwSolver(NineKwConfig{APIKey: apiKey, Timeout: timeout})
	})
}

// NineKwConfig contains configuration for the 9kw solver.
type NineKwConfig struct {
	APIKey       string
	Timeout      time.Duration
	BaseURL      string        // Override for testing
	PollInterval time.Duration // Override for testing (default: nineKwPollInterval)
}

// NewNineKwSolver creates a new 9kw solver instance.
func NewNineKwSolver(cfg NineKwConfig) *NineKwSolver {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = nineKwDefaultTimeout
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = nineKwBaseURL
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = nineKwPollInterval
	}

	return &NineKwSolver{
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
func (s *NineKwSolver) Name() string {
	return "9kw"
}

// IsConfigured returns true if the API key is set.
func (s *NineKwSolver) IsConfigured() bool {
	return s.apiKey != ""
}

// nineKwSubmitResponse is the JSON response from usercaptchaupload (json=1).
type nineKwSubmitResponse struct {
	CaptchaID string `json:"captchaid"`
	Error     string `json:"error"`
}

// nineKwResultResponse is the JSON response from usercaptchacorrectdata (json=1).
// try_again=1 means the captcha is still being worked on (keep polling). answer
// carries the solved token once ready, or the sentinel "ERROR NO USER" when no
// worker is available.
type nineKwResultResponse struct {
	Answer   string `json:"answer"`
	Message  string `json:"message"`
	TryAgain int    `json:"try_again"`
	Error    string `json:"error"`
}

// nineKwBalanceResponse is the JSON response from usercaptchaguthaben (json=1).
// 9kw has historically returned credits as either a JSON number or a string, so
// it is decoded leniently via json.Number.
type nineKwBalanceResponse struct {
	Credits json.Number `json:"credits"`
	Error   string      `json:"error"`
}

// SolveTurnstile is unsupported by 9kw — it has no Turnstile solving capability.
// Returning a rejected error (rather than blocking) lets SolverChain fall through
// to a Turnstile-capable provider.
func (s *NineKwSolver) SolveTurnstile(_ context.Context, _ *TurnstileRequest) (*TurnstileResult, error) {
	return nil, types.NewCaptchaRejectedError(s.Name(), "UNSUPPORTED", "9kw does not support Cloudflare Turnstile")
}

// SolveHCaptcha solves an hCaptcha challenge using the 9kw human solving pool.
func (s *NineKwSolver) SolveHCaptcha(ctx context.Context, req *HCaptchaRequest) (*CaptchaResult, error) {
	if !s.IsConfigured() {
		return nil, fmt.Errorf("9kw API key not configured")
	}

	startTime := time.Now()

	captchaID, err := s.submit(ctx, nineKwSourceHCaptcha, req.SiteKey, req.PageURL, req.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to submit hCaptcha: %w", err)
	}

	log.Debug().
		Str("captcha_id", captchaID).
		Str("sitekey", req.SiteKey[:min(10, len(req.SiteKey))]+"...").
		Msg("9kw hCaptcha task created")

	token, err := s.poll(ctx, captchaID)
	if err != nil {
		return nil, err
	}

	return &CaptchaResult{
		Token:     token,
		SolveTime: time.Since(startTime),
		Cost:      0, // 9kw bills in credits, not USD
		Provider:  s.Name(),
	}, nil
}

// submit uploads an interactive (token) captcha and returns the 9kw captcha id.
func (s *NineKwSolver) submit(ctx context.Context, oldsource, sitekey, pageURL, userAgent string) (string, error) {
	params := s.authParams()
	params.Set("action", nineKwActionUpload)
	params.Set("interactive", "1")
	params.Set("oldsource", oldsource)
	params.Set("file-upload-01", sitekey)
	params.Set("pageurl", pageURL)
	// Hint 9kw how long the solve may take (seconds), bounded to its accepted range.
	params.Set("maxtimeout", strconv.Itoa(clampInt(int(s.timeout.Seconds()), 60, 3999)))
	if userAgent != "" {
		params.Set("useragent", userAgent)
	}

	body, err := s.doRequest(ctx, params)
	if err != nil {
		return "", err
	}

	var resp nineKwSubmitResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("failed to parse 9kw submit response: %w", err)
	}
	if resp.Error != "" {
		return "", s.handleError(resp.Error, "")
	}
	if resp.CaptchaID == "" {
		return "", fmt.Errorf("9kw returned no captcha id")
	}
	return resp.CaptchaID, nil
}

// poll retrieves the solved token, blocking until ready, the budget expires, or
// the context is canceled.
func (s *NineKwSolver) poll(ctx context.Context, captchaID string) (string, error) {
	pollCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	// Initial delay before the first poll — a human has to pick the task up first.
	select {
	case <-pollCtx.Done():
		return "", types.NewCaptchaTimeoutError(s.Name(), captchaID)
	case <-ticker.C:
	}

	for {
		select {
		case <-pollCtx.Done():
			return "", types.NewCaptchaTimeoutError(s.Name(), captchaID)
		case <-ticker.C:
			token, ready, err := s.fetchResult(pollCtx, captchaID)
			if err != nil {
				return "", err
			}
			if ready {
				return token, nil
			}
			log.Debug().Str("captcha_id", captchaID).Msg("9kw task still processing")
		}
	}
}

// fetchResult performs a single result poll. ready is false (with nil error) when
// the task is still being solved.
func (s *NineKwSolver) fetchResult(ctx context.Context, captchaID string) (token string, ready bool, err error) {
	params := s.authParams()
	params.Set("action", nineKwActionResult)
	params.Set("id", captchaID)

	body, err := s.doRequest(ctx, params)
	if err != nil {
		return "", false, err
	}

	var resp nineKwResultResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", false, fmt.Errorf("failed to parse 9kw result response: %w", err)
	}
	if resp.Error != "" {
		return "", false, s.handleError(resp.Error, captchaID)
	}
	// Still being worked on.
	if resp.TryAgain == 1 || resp.Answer == "" {
		return "", false, nil
	}
	if resp.Answer == "ERROR NO USER" {
		return "", false, types.NewCaptchaRejectedError(s.Name(), "NO_USER", "no 9kw workers available")
	}
	return resp.Answer, true, nil
}

// Balance retrieves the current credit balance. 9kw reports credits, not USD.
func (s *NineKwSolver) Balance(ctx context.Context) (float64, error) {
	if !s.IsConfigured() {
		return 0, fmt.Errorf("9kw API key not configured")
	}

	params := s.authParams()
	params.Set("action", nineKwActionBalance)

	body, err := s.doRequest(ctx, params)
	if err != nil {
		return 0, err
	}

	var resp nineKwBalanceResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("failed to parse 9kw balance response: %w", err)
	}
	if resp.Error != "" {
		return 0, s.handleError(resp.Error, "")
	}
	credits, err := resp.Credits.Float64()
	if err != nil {
		return 0, fmt.Errorf("failed to parse 9kw credits: %w", err)
	}
	return credits, nil
}

// authParams returns a fresh parameter set seeded with the API key and json flag.
func (s *NineKwSolver) authParams() url.Values {
	params := url.Values{}
	params.Set("apikey", s.apiKey)
	params.Set("json", "1")
	return params
}

// doRequest issues a GET against the 9kw CGI endpoint and returns the raw body.
func (s *NineKwSolver) doRequest(ctx context.Context, params url.Values) ([]byte, error) {
	reqURL := s.baseURL + "?" + params.Encode()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	return respBody, nil
}

// handleError converts a 9kw error string (format: "NNNN message") into a typed
// error. Balance/credit and auth failures get specific types; everything else is
// a generic rejection so the chain advances to the next provider.
func (s *NineKwSolver) handleError(errStr, captchaID string) error {
	switch {
	case strings.Contains(errStr, "0011"), strings.Contains(errStr, "0024"): // balance / not enough credits
		return types.NewCaptchaBalanceError(s.Name())
	case strings.Contains(errStr, "0003"): // active API key not found
		return types.NewCaptchaRejectedError(s.Name(), "0003", "invalid API key")
	default:
		return &types.CaptchaError{
			Provider: s.Name(),
			TaskID:   captchaID,
			Code:     "",
			Message:  fmt.Sprintf("9kw error: %s", errStr),
			Err:      types.ErrCaptchaSolverRejected,
		}
	}
}

// clampInt bounds v to [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

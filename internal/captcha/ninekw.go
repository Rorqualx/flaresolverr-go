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
	"fmt"
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

	nineKwName = "9kw"

	// nineKwNoUser is the answer 9kw gives when no worker picked the task up.
	nineKwNoUser = "ERROR NO USER"
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
	Register(nineKwName, func(opts ProviderOptions) CaptchaSolver {
		return NewNineKwSolver(NineKwConfig(opts))
	})
}

// NineKwConfig contains configuration for the 9kw solver.
type NineKwConfig struct {
	APIKey       string
	Timeout      time.Duration
	BaseURL      string        // Override for testing and self-hosted gateways
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
	return nineKwName
}

// IsConfigured returns true if the API key is set.
func (s *NineKwSolver) IsConfigured() bool {
	return s.apiKey != ""
}

// nineKwSubmitResponse is the JSON response from usercaptchaupload (json=1).
// 9kw has sent the id as both a JSON number and a string.
type nineKwSubmitResponse struct {
	CaptchaID flexString `json:"captchaid"`
	Error     flexString `json:"error"`
}

// nineKwResultResponse is the JSON response from usercaptchacorrectdata (json=1).
// try_again=1 means the captcha is still being worked on (keep polling). answer
// carries the solved token once ready, or the sentinel "ERROR NO USER" when no
// worker is available.
type nineKwResultResponse struct {
	Answer   string     `json:"answer"`
	Message  string     `json:"message"`
	TryAgain flexString `json:"try_again"`
	Error    flexString `json:"error"`
}

// nineKwBalanceResponse is the JSON response from usercaptchaguthaben (json=1).
// 9kw has historically returned credits as either a JSON number or a string.
type nineKwBalanceResponse struct {
	Credits flexString `json:"credits"`
	Error   flexString `json:"error"`
}

// SolveTurnstile is unsupported by 9kw — it has no Turnstile solving capability.
// Returning a rejected error (rather than blocking) lets SolverChain fall through
// to a Turnstile-capable provider. Nothing is sent to 9kw, so no budget is spent.
func (s *NineKwSolver) SolveTurnstile(_ context.Context, _ *TurnstileRequest) (*TurnstileResult, error) {
	return nil, notCreated(types.NewCaptchaRejectedError(nineKwName, "UNSUPPORTED", "9kw does not support Cloudflare Turnstile"))
}

// SolveHCaptcha solves an hCaptcha challenge using the 9kw human solving pool.
func (s *NineKwSolver) SolveHCaptcha(ctx context.Context, req *HCaptchaRequest) (*CaptchaResult, error) {
	if !s.IsConfigured() {
		return nil, notCreated(fmt.Errorf("%s API key not configured", nineKwName))
	}

	startTime := time.Now()

	captchaID, err := s.submit(ctx, nineKwSourceHCaptcha, req.SiteKey, req.PageURL, req.UserAgent)
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("captcha_id", captchaID).
		Str("sitekey", sitekeyPreview(req.SiteKey)).
		Msg("9kw hCaptcha task created")

	token, err := pollTask(ctx, pollConfig{
		provider: nineKwName,
		taskID:   captchaID,
		timeout:  s.timeout,
		interval: s.pollInterval,
	}, func(pollCtx context.Context) (string, bool, error) {
		return s.fetchResult(pollCtx, captchaID)
	})
	if err != nil {
		return nil, err
	}

	return &CaptchaResult{
		Token:     token,
		SolveTime: time.Since(startTime),
		Cost:      0, // 9kw bills in credits, not USD
		Provider:  nineKwName,
	}, nil
}

// submit uploads an interactive (token) captcha and returns the 9kw captcha id.
// A definitive refusal is returned as a "not created" error.
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

	var resp nineKwSubmitResponse
	if err := s.get(ctx, params, &resp); err != nil {
		return "", createFailure(fmt.Errorf("%s: failed to submit captcha: %w", nineKwName, err))
	}
	if resp.Error != "" {
		return "", notCreated(s.handleError(string(resp.Error), ""))
	}
	if resp.CaptchaID == "" {
		return "", notCreated(fmt.Errorf("%s returned no captcha id", nineKwName))
	}
	return string(resp.CaptchaID), nil
}

// fetchResult performs a single result poll. ready is false (with nil error) when
// the task is still being solved.
func (s *NineKwSolver) fetchResult(ctx context.Context, captchaID string) (token string, ready bool, err error) {
	params := s.authParams()
	params.Set("action", nineKwActionResult)
	params.Set("id", captchaID)

	var resp nineKwResultResponse
	if err := s.get(ctx, params, &resp); err != nil {
		return "", false, err
	}
	if resp.Error != "" {
		return "", false, s.handleError(string(resp.Error), captchaID)
	}
	if resp.Answer == nineKwNoUser {
		return "", false, types.NewCaptchaRejectedError(nineKwName, "NO_USER", "no 9kw workers available")
	}
	// Still being worked on.
	if resp.TryAgain.float() != 0 || resp.Answer == "" {
		return "", false, nil
	}
	return resp.Answer, true, nil
}

// Balance retrieves the current credit balance. 9kw reports credits, not USD.
func (s *NineKwSolver) Balance(ctx context.Context) (float64, error) {
	if !s.IsConfigured() {
		return 0, fmt.Errorf("%s API key not configured", nineKwName)
	}

	params := s.authParams()
	params.Set("action", nineKwActionBalance)

	var resp nineKwBalanceResponse
	if err := s.get(ctx, params, &resp); err != nil {
		return 0, fmt.Errorf("%s: failed to get balance: %w", nineKwName, err)
	}
	if resp.Error != "" {
		return 0, s.handleError(string(resp.Error), "")
	}
	credits, err := strconv.ParseFloat(string(resp.Credits), 64)
	if err != nil {
		return 0, fmt.Errorf("%s: failed to parse credits", nineKwName)
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

// get issues a GET against the 9kw CGI endpoint and decodes the JSON response.
// The request URL carries the API key; doJSON keeps it out of every error.
func (s *NineKwSolver) get(ctx context.Context, params url.Values, out interface{}) error {
	return doJSON(ctx, s.httpClient, http.MethodGet, s.baseURL+"?"+params.Encode(), nil, out)
}

// handleError converts a 9kw error string (format: "NNNN message") into a typed
// error. Balance/credit and auth failures get specific types; everything else is
// a generic rejection so the chain advances to the next provider.
func (s *NineKwSolver) handleError(errStr, captchaID string) error {
	switch {
	case strings.Contains(errStr, "0011"), strings.Contains(errStr, "0024"): // balance / not enough credits
		return types.NewCaptchaBalanceError(nineKwName)
	case strings.Contains(errStr, "0003"): // active API key not found
		return types.NewCaptchaRejectedError(nineKwName, "0003", "invalid API key")
	default:
		return &types.CaptchaError{
			Provider: nineKwName,
			TaskID:   captchaID,
			Code:     "",
			Message:  fmt.Sprintf("9kw error: %s", providerMessage(errStr, "unknown", s.apiKey)),
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

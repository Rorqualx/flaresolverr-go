// Package solver provides Cloudflare challenge detection and resolution.
// It handles various challenge types including JavaScript challenges and Turnstile.
package solver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/security"
	"github.com/Rorqualx/flaresolverr-go/internal/selectors"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// ChallengeType represents the type of challenge detected.
type ChallengeType int

const (
	ChallengeNone ChallengeType = iota
	ChallengeJavaScript
	ChallengeTurnstile
	ChallengeAccessDenied
)

// Result contains the outcome of a solve attempt.
type Result struct {
	Success        bool
	StatusCode     int
	HTML           string
	Cookies        []*proto.NetworkCookie
	UserAgent      string
	URL            string
	Screenshot     string // Base64 encoded PNG screenshot
	TurnstileToken string // cf-turnstile-response token if present
}

// SolveOptions contains options for a solve request.
type SolveOptions struct {
	URL           string
	Timeout       time.Duration
	Cookies       []types.RequestCookie
	Proxy         *types.Proxy
	PostData      string
	IsPost        bool
	Screenshot    bool // Capture screenshot after solve
	DisableMedia  bool // Disable loading of media (images, CSS, fonts)
	WaitInSeconds int  // Wait N seconds before returning the response
}

// Solver handles Cloudflare challenge resolution.
type Solver struct {
	pool      *browser.Pool
	userAgent string
}

// New creates a new Solver instance.
func New(pool *browser.Pool, userAgent string) *Solver {
	return &Solver{
		pool:      pool,
		userAgent: userAgent,
	}
}

// sleepWithContext sleeps for the specified duration or until context is cancelled.
// Returns true if the sleep completed normally, false if interrupted by context cancellation.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// setupMediaBlocking enables request interception to block media resources.
// This reduces bandwidth and speeds up page loads by blocking images, stylesheets, fonts, and media.
// Returns a cleanup function that should be deferred.
func setupMediaBlocking(page *rod.Page) func() {
	router := page.HijackRequests()

	router.MustAdd("*", func(ctx *rod.Hijack) {
		resourceType := ctx.Request.Type()
		// Block images, stylesheets, fonts, and media
		switch resourceType {
		case proto.NetworkResourceTypeImage,
			proto.NetworkResourceTypeStylesheet,
			proto.NetworkResourceTypeFont,
			proto.NetworkResourceTypeMedia:
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		ctx.ContinueRequest(&proto.FetchContinueRequest{})
	})

	go router.Run()

	return func() {
		_ = router.Stop()
	}
}

// Solve navigates to a URL and attempts to solve any Cloudflare challenges.
// It returns the page content after challenge resolution.
func (s *Solver) Solve(ctx context.Context, opts *SolveOptions) (*Result, error) {
	// Validate timeout (Bug 9: zero timeout validation)
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive, got %v", opts.Timeout)
	}

	// Ensure minimum timeout of 1 second
	timeout := opts.Timeout
	if timeout < time.Second {
		log.Warn().Dur("requested", timeout).Msg("Timeout too short, using 1 second minimum")
		timeout = time.Second
	}

	log.Info().
		Str("url", opts.URL).
		Dur("timeout", timeout).
		Bool("is_post", opts.IsPost).
		Int("cookies_count", len(opts.Cookies)).
		Bool("has_proxy", opts.Proxy != nil).
		Bool("disable_media", opts.DisableMedia).
		Int("wait_seconds", opts.WaitInSeconds).
		Msg("Starting solve attempt")

	// Acquire browser from pool
	browserInstance, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, types.NewPoolAcquireError("failed to acquire browser", err)
	}
	defer s.pool.Release(browserInstance)

	// Create timeout context for the solve operation
	solveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var page *rod.Page

	// For POST requests, we need a special approach because stealth scripts
	// conflict with form creation JavaScript. We use a regular page and
	// apply stealth manually after the POST navigation.
	if opts.IsPost && opts.PostData != "" {
		// Create a regular page for POST (stealth scripts break form JS)
		page, err = browserInstance.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			return nil, fmt.Errorf("failed to create page: %w", err)
		}
		defer page.Close()

		// Set user agent
		if s.userAgent != "" {
			if err := browser.SetUserAgent(page, s.userAgent); err != nil {
				log.Warn().Err(err).Msg("Failed to set user agent")
			}
		}

		// Set viewport
		if err := browser.SetViewport(page, 1920, 1080); err != nil {
			log.Warn().Err(err).Msg("Failed to set viewport")
		}

		// Set up media blocking if requested
		if opts.DisableMedia {
			mediaCleanup := setupMediaBlocking(page)
			defer mediaCleanup()
			log.Debug().Msg("Media blocking enabled")
		}

		// Set up proxy authentication if needed
		// Bug 1: Capture cleanup function to prevent goroutine leaks
		var proxyCleanup func()
		if opts.Proxy != nil && opts.Proxy.URL != "" {
			var proxyErr error
			proxyCleanup, proxyErr = browser.SetPageProxy(solveCtx, page, &browser.ProxyConfig{
				URL:      opts.Proxy.URL,
				Username: opts.Proxy.Username,
				Password: opts.Proxy.Password,
			})
			if proxyErr != nil {
				log.Warn().Err(proxyErr).Msg("Failed to set up proxy")
			}
		}
		if proxyCleanup != nil {
			defer proxyCleanup()
		}

		// Set cookies before navigation
		if len(opts.Cookies) > 0 {
			if err := s.setCookies(page, opts.Cookies, opts.URL); err != nil {
				log.Warn().Err(err).Msg("Failed to set cookies")
			}
		}

		// POST request via form submission
		if err := s.navigatePost(page.Context(solveCtx), opts.URL, opts.PostData); err != nil {
			return nil, err
		}
	} else {
		// For GET requests, use stealth page
		page = stealth.MustPage(browserInstance)
		defer page.Close()

		// Set user agent
		if s.userAgent != "" {
			if err := browser.SetUserAgent(page, s.userAgent); err != nil {
				log.Warn().Err(err).Msg("Failed to set user agent")
			}
		}

		// Set viewport
		if err := browser.SetViewport(page, 1920, 1080); err != nil {
			log.Warn().Err(err).Msg("Failed to set viewport")
		}

		// Set up media blocking if requested
		if opts.DisableMedia {
			mediaCleanup := setupMediaBlocking(page)
			defer mediaCleanup()
			log.Debug().Msg("Media blocking enabled")
		}

		// Set up proxy authentication if needed
		// Bug 1: Capture cleanup function to prevent goroutine leaks
		var proxyCleanup func()
		if opts.Proxy != nil && opts.Proxy.URL != "" {
			var proxyErr error
			proxyCleanup, proxyErr = browser.SetPageProxy(solveCtx, page, &browser.ProxyConfig{
				URL:      opts.Proxy.URL,
				Username: opts.Proxy.Username,
				Password: opts.Proxy.Password,
			})
			if proxyErr != nil {
				log.Warn().Err(proxyErr).Msg("Failed to set up proxy")
			}
		}
		if proxyCleanup != nil {
			defer proxyCleanup()
		}

		// Set cookies before navigation
		if len(opts.Cookies) > 0 {
			if err := s.setCookies(page, opts.Cookies, opts.URL); err != nil {
				log.Warn().Err(err).Msg("Failed to set cookies")
			}
		}

		// Regular GET request
		if err := page.Context(solveCtx).Navigate(opts.URL); err != nil {
			return nil, err
		}
	}

	// Wait for initial load
	if err := page.Context(solveCtx).WaitLoad(); err != nil {
		log.Warn().Err(err).Msg("WaitLoad failed, continuing anyway")
	}

	// Main solve loop
	result, err := s.solveLoop(solveCtx, page, opts.URL, opts.Screenshot)
	if err != nil {
		return nil, err
	}

	// Wait additional time if requested (waitInSeconds)
	if opts.WaitInSeconds > 0 {
		waitDuration := time.Duration(opts.WaitInSeconds) * time.Second
		log.Debug().Int("seconds", opts.WaitInSeconds).Msg("Waiting additional time before returning")
		if !sleepWithContext(solveCtx, waitDuration) {
			log.Warn().Msg("Wait interrupted by context cancellation")
		}
	}

	return result, nil
}

// setCookies sets cookies on the page before navigation.
func (s *Solver) setCookies(page *rod.Page, cookies []types.RequestCookie, targetURL string) error {
	if len(cookies) == 0 {
		return nil
	}

	// Parse URL to get domain
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	domain := parsedURL.Hostname()

	cdpCookies := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, c := range cookies {
		// Sanitize cookie domain to prevent setting cookies on arbitrary domains
		cookieDomain := security.SanitizeCookieDomain(c.Domain, domain)

		cookiePath := c.Path
		if cookiePath == "" {
			cookiePath = "/"
		}

		cdpCookies = append(cdpCookies, &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   cookieDomain,
			Path:     cookiePath,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		})
	}

	log.Debug().
		Int("cookie_count", len(cdpCookies)).
		Str("domain", domain).
		Msg("Setting cookies")

	return page.SetCookies(cdpCookies)
}

// navigatePost performs a POST request by injecting and submitting a form.
// This function is called with a regular (non-stealth) page to avoid JS conflicts.
func (s *Solver) navigatePost(page *rod.Page, targetURL string, postData string) error {
	log.Debug().
		Str("url", targetURL).
		Int("post_data_len", len(postData)).
		Msg("Performing POST request")

	// Parse the URL to get the base domain
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Navigate to the target domain first to establish proper page context
	// This ensures all browser APIs are properly initialized
	baseURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
	if err := page.Navigate(baseURL); err != nil {
		return fmt.Errorf("failed to navigate to base URL: %w", err)
	}

	// Wait for page to be ready
	if err := page.WaitLoad(); err != nil {
		log.Debug().Err(err).Msg("WaitLoad on base URL failed")
	}

	// Give the page time to fully initialize, but respect context cancellation
	if !sleepWithContext(page.GetContext(), 500*time.Millisecond) {
		return fmt.Errorf("context cancelled during POST navigation: %w", page.GetContext().Err())
	}

	// Build form fields JavaScript
	fieldsJS := s.buildFormFieldsJS(postData)

	// Escape the URL for JavaScript
	escapedURL := strings.ReplaceAll(targetURL, "\\", "\\\\")
	escapedURL = strings.ReplaceAll(escapedURL, "'", "\\'")
	escapedURL = strings.ReplaceAll(escapedURL, "\n", "\\n")
	escapedURL = strings.ReplaceAll(escapedURL, "\r", "\\r")

	// Use Runtime.evaluate directly via CDP to avoid Rod's wrapper
	evalResult, err := proto.RuntimeEvaluate{
		Expression: fmt.Sprintf(`
			(function() {
				var form = document.createElement('form');
				form.method = 'POST';
				form.action = '%s';
				form.style.display = 'none';
				%s
				document.body.appendChild(form);
				form.submit();
				return 'submitted';
			})()
		`, escapedURL, fieldsJS),
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		return fmt.Errorf("failed to submit POST form: %w", err)
	}

	if evalResult.ExceptionDetails != nil {
		return fmt.Errorf("failed to submit POST form: %s", evalResult.ExceptionDetails.Text)
	}

	// Wait for navigation to complete
	if err := page.WaitLoad(); err != nil {
		log.Warn().Err(err).Msg("WaitLoad after POST failed, continuing anyway")
	}

	return nil
}

// buildFormFieldsJS generates JavaScript code to add form fields.
// Uses JSON encoding for proper escaping to prevent JavaScript injection.
func (s *Solver) buildFormFieldsJS(postData string) string {
	if postData == "" {
		return ""
	}

	var builder strings.Builder
	pairs := strings.Split(postData, "&")
	for i, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			// URL decode the key and value
			key, _ := url.QueryUnescape(parts[0])
			value, _ := url.QueryUnescape(parts[1])

			// Use JSON encoding for proper escaping of all special characters
			// This safely handles quotes, backslashes, newlines, unicode, and script tags
			keyJSON, err := json.Marshal(key)
			if err != nil {
				log.Warn().Err(err).Str("key", key).Msg("Failed to JSON encode form key")
				continue
			}
			valueJSON, err := json.Marshal(value)
			if err != nil {
				log.Warn().Err(err).Str("key", key).Msg("Failed to JSON encode form value")
				continue
			}

			// Use unique variable names to avoid redeclaration
			// JSON-encoded strings include quotes, so use them directly
			builder.WriteString(fmt.Sprintf(`
				var input%d = document.createElement('input');
				input%d.type = 'hidden';
				input%d.name = %s;
				input%d.value = %s;
				form.appendChild(input%d);`, i, i, i, keyJSON, i, valueJSON, i))
		}
	}
	return builder.String()
}

// Challenge titles that indicate a challenge is in progress
var challengeTitles = []string{
	"just a moment",
	"checking your browser",
	"ddos-guard",
	"please wait",
	"attention required",
}

// Challenge selectors that indicate a challenge is in progress
var challengeSelectors = []string{
	"#cf-challenge-running",
	".ray_id",
	"#turnstile-wrapper",
	"#cf-wrapper",
	"#challenge-running",
	"#challenge-stage",
	"#cf-spinner-please-wait",
	"#cf-spinner-redirecting",
}

// solveLoop repeatedly checks for and attempts to solve challenges.
// Uses the same approach as Python FlareSolverr: check title and selectors.
func (s *Solver) solveLoop(ctx context.Context, page *rod.Page, url string, captureScreenshot bool) (*Result, error) {
	const pollInterval = 1 * time.Second

	// Calculate max attempts from context deadline (Bug 3: poll attempts vs timeout mismatch)
	maxAttempts := 300 // Fallback: 5 minutes at 1s intervals
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		maxAttempts = int(remaining/pollInterval) + 1
		if maxAttempts < 1 {
			maxAttempts = 1
		}
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, types.NewChallengeTimeoutError(url)
		default:
		}

		// Get page title
		title, err := s.getPageTitle(page)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to get page title")
			// Use context-aware sleep (Bug 2: time.Sleep ignores context)
			if !sleepWithContext(ctx, pollInterval) {
				return nil, types.NewChallengeTimeoutError(url)
			}
			continue
		}

		// Check if title indicates a challenge
		titleLower := strings.ToLower(title)
		challengeInTitle := false
		for _, t := range challengeTitles {
			if strings.Contains(titleLower, t) {
				challengeInTitle = true
				break
			}
		}

		// Check if any challenge selector is present
		challengeSelector := s.findChallengeSelector(page)

		log.Debug().
			Int("attempt", attempt+1).
			Int("max_attempts", maxAttempts).
			Str("title", title).
			Bool("challenge_in_title", challengeInTitle).
			Str("challenge_selector", challengeSelector).
			Msg("Challenge detection")

		// If no challenge indicators, we're done
		if !challengeInTitle && challengeSelector == "" {
			log.Info().Str("title", title).Msg("Challenge solved or no challenge present")
			return s.buildResult(page, url, captureScreenshot)
		}

		// Check for access denied
		html, _ := page.HTML()
		if html != "" && s.detectChallenge(html) == ChallengeAccessDenied {
			return nil, types.NewAccessDeniedError(url)
		}

		// If Turnstile is present, try to click it
		if challengeSelector == "#turnstile-wrapper" {
			log.Debug().Msg("Turnstile detected, attempting to solve...")
			if err := s.solveTurnstile(ctx, page); err != nil {
				log.Debug().Err(err).Msg("Turnstile solve attempt failed")
			}
		}

		// Wait and retry with context-aware sleep (Bug 2)
		if !sleepWithContext(ctx, pollInterval) {
			return nil, types.NewChallengeTimeoutError(url)
		}
	}

	return nil, types.NewChallengeTimeoutError(url)
}

// getPageTitle safely gets the page title.
func (s *Solver) getPageTitle(page *rod.Page) (string, error) {
	info, err := page.Info()
	if err != nil {
		return "", err
	}
	return info.Title, nil
}

// findChallengeSelector checks if any challenge selector is present on the page.
func (s *Solver) findChallengeSelector(page *rod.Page) string {
	for _, selector := range challengeSelectors {
		has, _, _ := page.Has(selector)
		if has {
			return selector
		}
	}
	return ""
}

// detectChallenge analyzes HTML to determine the challenge type.
func (s *Solver) detectChallenge(html string) ChallengeType {
	htmlLower := strings.ToLower(html)
	sel := selectors.Get()

	// Check for access denied
	for _, pattern := range sel.AccessDenied {
		if strings.Contains(htmlLower, pattern) && strings.Contains(htmlLower, "cloudflare") {
			return ChallengeAccessDenied
		}
	}

	// Check for Turnstile challenge
	for _, pattern := range sel.Turnstile {
		if strings.Contains(htmlLower, pattern) {
			return ChallengeTurnstile
		}
	}

	// Check for JavaScript challenge
	for _, pattern := range sel.JavaScript {
		if strings.Contains(htmlLower, pattern) {
			return ChallengeJavaScript
		}
	}

	return ChallengeNone
}

// solveTurnstile attempts to solve the Turnstile challenge.
// Uses the same approach as Python FlareSolverr: keyboard navigation.
// Properly releases DOM element references to prevent memory leaks.
func (s *Solver) solveTurnstile(ctx context.Context, page *rod.Page) error {
	log.Debug().Msg("Attempting to solve Turnstile challenge")

	// Method 1: Try keyboard navigation (Python FlareSolverr approach)
	// This works better because it doesn't require finding elements in iframes
	if err := s.solveTurnstileKeyboard(page); err == nil {
		return nil
	}

	// Method 2: Fallback to direct iframe click
	return s.solveTurnstileClick(page)
}

// solveTurnstileKeyboard uses keyboard navigation to solve Turnstile.
// This matches Python FlareSolverr's click_verify() function.
func (s *Solver) solveTurnstileKeyboard(page *rod.Page) error {
	log.Debug().Msg("Trying keyboard navigation for Turnstile")

	ctx := page.GetContext()

	// Wait a moment for Turnstile to fully load, but respect context (Bug 2)
	if !sleepWithContext(ctx, 2*time.Second) {
		return fmt.Errorf("context cancelled during Turnstile solve")
	}

	keyboard := page.Keyboard

	// Tab through elements to reach the Turnstile checkbox
	// Python uses 10 tabs by default
	for i := 0; i < 10; i++ {
		if err := keyboard.Press(input.Tab); err != nil {
			log.Debug().Err(err).Int("tab", i).Msg("Tab press failed")
			continue
		}
		// Context-aware sleep (Bug 2)
		if !sleepWithContext(ctx, 200*time.Millisecond) {
			return fmt.Errorf("context cancelled during Turnstile solve")
		}
	}

	// Press Space to check the checkbox
	if err := keyboard.Press(input.Space); err != nil {
		log.Debug().Err(err).Msg("Space press failed")
		return err
	}

	log.Info().Msg("Sent keyboard Tab+Space for Turnstile")

	// Wait a moment for the click to register, but respect context (Bug 2)
	if !sleepWithContext(ctx, 1*time.Second) {
		return fmt.Errorf("context cancelled during Turnstile solve")
	}

	// Try to find and click "Verify you are human" button
	if btn, err := page.Element("//button[contains(text(),'Verify')]"); err == nil {
		if clickErr := btn.Click(proto.InputMouseButtonLeft, 1); clickErr == nil {
			log.Info().Msg("Clicked Verify button")
		}
		_ = btn.Release()
	}

	return nil
}

// solveTurnstileClick attempts to directly click the Turnstile checkbox in iframe.
func (s *Solver) solveTurnstileClick(page *rod.Page) error {
	log.Debug().Msg("Trying direct iframe click for Turnstile")

	sel := selectors.Get()

	// Find all iframes on the page
	iframes, err := page.Elements("iframe")
	if err != nil {
		return err
	}

	// CRITICAL: Release all iframes when done to prevent memory leak
	defer func() {
		for _, iframe := range iframes {
			_ = iframe.Release()
		}
	}()

	for _, iframe := range iframes {
		// Get iframe src
		src, err := iframe.Attribute("src")
		if err != nil || src == nil {
			continue
		}

		if strings.Contains(*src, sel.TurnstileFramePattern) {
			log.Debug().Str("frame_src", *src).Msg("Found Turnstile frame")

			// Get the frame's page object
			frame, err := iframe.Frame()
			if err != nil {
				log.Debug().Err(err).Msg("Failed to get frame")
				continue
			}

			// Look for the checkbox using configured selectors
			for _, selector := range sel.TurnstileSelectors {
				element, err := frame.Element(selector)
				if err != nil {
					continue
				}

				// Try to click the element, then release it immediately
				clickErr := element.Click(proto.InputMouseButtonLeft, 1)
				_ = element.Release() // Release element after use

				if clickErr != nil {
					log.Debug().Err(clickErr).Str("selector", selector).Msg("Click failed")
					continue
				}

				log.Info().Str("selector", selector).Msg("Clicked Turnstile checkbox")
				return nil
			}
		}
	}

	return types.ErrTurnstileFailed
}

// Maximum response size to prevent memory exhaustion (10MB)
const maxResponseSize = 10 * 1024 * 1024

// validateResponseURL validates the current page URL to detect DNS rebinding attacks.
// This should be called after navigation to ensure we haven't been redirected to a blocked IP.
func (s *Solver) validateResponseURL(page *rod.Page) error {
	info, err := page.Info()
	if err != nil {
		// Can't get page info - allow to continue
		log.Debug().Err(err).Msg("Could not get page info for URL validation")
		return nil
	}

	if info.URL == "" || info.URL == "about:blank" {
		return nil
	}

	// Re-validate the response URL to detect DNS rebinding
	if err := security.ValidateURL(info.URL); err != nil {
		log.Warn().
			Str("url", info.URL).
			Err(err).
			Msg("Response URL failed validation (possible DNS rebinding)")
		return fmt.Errorf("response URL validation failed: %w", err)
	}

	return nil
}

// buildResult constructs the result after successful solve.
// Fetches HTML from page - prefer buildResultWithHTML if you already have HTML.
func (s *Solver) buildResult(page *rod.Page, url string, captureScreenshot bool) (*Result, error) {
	// Validate response URL to detect DNS rebinding attacks
	if err := s.validateResponseURL(page); err != nil {
		return nil, err
	}

	html, err := page.HTML()
	if err != nil {
		return nil, err
	}
	return s.buildResultWithHTML(page, url, html, captureScreenshot)
}

// buildResultWithHTML constructs the result using pre-fetched HTML.
// This avoids redundant HTML fetching when HTML is already available.
func (s *Solver) buildResultWithHTML(page *rod.Page, url string, html string, captureScreenshot bool) (*Result, error) {
	// Limit response size to prevent memory exhaustion
	if len(html) > maxResponseSize {
		log.Warn().
			Int("size", len(html)).
			Int("max", maxResponseSize).
			Msg("Response truncated due to size limit")
		html = html[:maxResponseSize]
	}

	cookies, err := page.Cookies(nil)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get cookies")
		cookies = nil
	}

	// Get current URL (may have been redirected)
	info, err := page.Info()
	currentURL := url
	if err == nil && info.URL != "" {
		currentURL = info.URL
	}

	// Extract Turnstile token if present
	turnstileToken := s.extractTurnstileToken(page)
	if turnstileToken != "" {
		log.Debug().Str("token_prefix", turnstileToken[:min(20, len(turnstileToken))]).Msg("Extracted Turnstile token")
	}

	// Capture screenshot if requested
	var screenshotBase64 string
	if captureScreenshot {
		screenshotData, err := s.captureScreenshot(page)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to capture screenshot")
		} else {
			screenshotBase64 = base64.StdEncoding.EncodeToString(screenshotData)
			log.Debug().Int("size", len(screenshotData)).Msg("Screenshot captured")
		}
	}

	log.Info().
		Str("url", currentURL).
		Int("cookies_count", len(cookies)).
		Int("html_length", len(html)).
		Bool("has_turnstile_token", turnstileToken != "").
		Bool("has_screenshot", screenshotBase64 != "").
		Msg("Solve completed successfully")

	return &Result{
		Success:        true,
		StatusCode:    200, // Assume success if we got here
		HTML:          html,
		Cookies:       cookies,
		UserAgent:     s.userAgent,
		URL:           currentURL,
		TurnstileToken: turnstileToken,
		Screenshot:    screenshotBase64,
	}, nil
}

// extractTurnstileToken extracts the cf-turnstile-response token from the page.
// This matches Python FlareSolverr's get_turnstile_token() function.
// Uses a timeout to prevent hanging on element queries.
func (s *Solver) extractTurnstileToken(page *rod.Page) string {
	// Use JavaScript evaluation to avoid blocking element queries
	// This is faster and more reliable than iterating elements
	result, err := proto.RuntimeEvaluate{
		Expression: `(function() {
			// Try turnstile API first
			if (window.turnstile && typeof window.turnstile.getResponse === 'function') {
				try {
					var token = window.turnstile.getResponse();
					if (token) return token;
				} catch(e) {}
			}
			// Try input element
			var input = document.querySelector('input[name="cf-turnstile-response"]');
			if (input && input.value) return input.value;
			// Try textarea
			var textarea = document.querySelector('textarea[name="cf-turnstile-response"]');
			if (textarea && textarea.value) return textarea.value;
			// Try recaptcha fallback
			var recaptcha = document.querySelector('input[name="g-recaptcha-response"]');
			if (recaptcha && recaptcha.value) return recaptcha.value;
			return '';
		})()`,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract Turnstile token")
		return ""
	}

	if result.Result.Type == proto.RuntimeRemoteObjectTypeString {
		token := result.Result.Value.Str()
		return token
	}

	return ""
}

// captureScreenshot captures a PNG screenshot of the page.
func (s *Solver) captureScreenshot(page *rod.Page) ([]byte, error) {
	// Use full page screenshot
	screenshot, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: nil, // PNG doesn't use quality
	})
	if err != nil {
		return nil, fmt.Errorf("screenshot capture failed: %w", err)
	}
	return screenshot, nil
}

// SolveWithPage solves a challenge using an existing page (for session support).
func (s *Solver) SolveWithPage(ctx context.Context, page *rod.Page, opts *SolveOptions) (*Result, error) {
	log.Info().
		Str("url", opts.URL).
		Bool("disable_media", opts.DisableMedia).
		Int("wait_seconds", opts.WaitInSeconds).
		Msg("Starting solve with existing page")

	// Apply stealth patches
	if err := browser.ApplyStealthToPage(page); err != nil {
		log.Warn().Err(err).Msg("Failed to apply stealth patches")
	}

	// Set up media blocking if requested
	if opts.DisableMedia {
		mediaCleanup := setupMediaBlocking(page)
		defer mediaCleanup()
		log.Debug().Msg("Media blocking enabled")
	}

	// Set cookies if provided
	if len(opts.Cookies) > 0 {
		if err := s.setCookies(page, opts.Cookies, opts.URL); err != nil {
			log.Warn().Err(err).Msg("Failed to set cookies")
		}
	}

	// Create timeout context
	solveCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// Navigate (GET or POST)
	// Use page.Context() inline to avoid reassigning the page variable
	if opts.IsPost && opts.PostData != "" {
		if err := s.navigatePost(page.Context(solveCtx), opts.URL, opts.PostData); err != nil {
			return nil, err
		}
	} else {
		if err := page.Context(solveCtx).Navigate(opts.URL); err != nil {
			return nil, err
		}
	}

	// Wait for load
	if err := page.Context(solveCtx).WaitLoad(); err != nil {
		log.Warn().Err(err).Msg("WaitLoad failed, continuing anyway")
	}

	result, err := s.solveLoop(solveCtx, page, opts.URL, opts.Screenshot)
	if err != nil {
		return nil, err
	}

	// Wait additional time if requested (waitInSeconds)
	if opts.WaitInSeconds > 0 {
		waitDuration := time.Duration(opts.WaitInSeconds) * time.Second
		log.Debug().Int("seconds", opts.WaitInSeconds).Msg("Waiting additional time before returning")
		if !sleepWithContext(solveCtx, waitDuration) {
			log.Warn().Msg("Wait interrupted by context cancellation")
		}
	}

	return result, nil
}

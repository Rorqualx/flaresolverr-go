// Package solver provides Cloudflare challenge detection and resolution.
// It handles various challenge types including JavaScript challenges and Turnstile.
package solver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/rs/zerolog/log"
	"github.com/ysmood/gson"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/security"
	"github.com/Rorqualx/flaresolverr-go/internal/selectors"
	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// ChallengeType represents the type of challenge detected.
type ChallengeType int

// Challenge type values.
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
	HTMLTruncated  bool // Fix #15: Flag indicating HTML was truncated due to size limit
	Cookies        []*proto.NetworkCookie
	CookieError    string // Non-empty if cookies could not be retrieved
	UserAgent      string
	URL            string
	Screenshot     string // Base64 encoded PNG screenshot
	TurnstileToken string // cf-turnstile-response token if present

	// Extended extraction for debugging/advanced use
	LocalStorage    map[string]string // All localStorage key-value pairs
	SessionStorage  map[string]string // All sessionStorage key-value pairs
	ResponseHeaders map[string]string // Headers from the final navigation response
}

// SolveOptions contains options for a solve request.
type SolveOptions struct {
	URL            string
	Timeout        time.Duration
	Cookies        []types.RequestCookie
	Proxy          *types.Proxy
	PostData       string
	ContentType    string            // Content type for POST: "application/json" or "application/x-www-form-urlencoded"
	Headers        map[string]string // Custom HTTP headers to send with the request
	IsPost         bool
	Screenshot     bool   // Capture screenshot after solve
	DisableMedia   bool   // Disable loading of media (images, CSS, fonts)
	WaitInSeconds  int    // Wait N seconds before returning the response
	ExpectedIP     net.IP // Expected IP from DNS resolution for pinning (nil to skip)
	TabsTillVerify int    // Number of Tab presses to reach Turnstile checkbox (default: 10)

	// SkipResponseValidation disables response URL validation (for testing only).
	// WARNING: Do not enable in production - this disables SSRF protection.
	SkipResponseValidation bool
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

// sleepWithContext sleeps for the specified duration or until context is canceled.
// Returns true if the sleep completed normally, false if interrupted by context cancellation.
//
// Fix MEDIUM: Uses time.NewTimer instead of time.After to prevent timer leak
// when context is canceled before timer fires.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop() // Ensure timer is cleaned up

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// safeEvalResultString safely extracts a string value from a RuntimeEvaluate result.
// Returns an empty string if the result is nil, has an exception, or is not a string type.
// This prevents nil pointer panics when accessing eval results.
func safeEvalResultString(result *proto.RuntimeEvaluateResult) string {
	if result == nil || result.Result == nil {
		return ""
	}
	if result.ExceptionDetails != nil {
		return ""
	}
	// gson.JSON uses Nil() method to check for nil values
	if result.Result.Value.Nil() {
		return ""
	}
	if result.Result.Type != proto.RuntimeRemoteObjectTypeString {
		return ""
	}
	return result.Result.Value.Str()
}

// Fix #13: setupProxyAuth sets up proxy authentication for a page if needed.
// Returns a cleanup function and error. The cleanup function is safe to call
// even if it's nil (will be a no-op). Errors are now propagated to caller.
func setupProxyAuth(ctx context.Context, page *rod.Page, proxy *types.Proxy) (func(), error) {
	if proxy == nil || proxy.URL == "" {
		return func() {}, nil
	}

	cleanup, err := browser.SetPageProxy(ctx, page, &browser.ProxyConfig{
		URL:      proxy.URL,
		Username: proxy.Username,
		Password: proxy.Password,
	})
	if err != nil {
		log.Warn().Err(err).Msg("Failed to set up proxy")
		return func() {}, fmt.Errorf("failed to set up proxy authentication: %w", err)
	}
	return cleanup, nil
}

// setupMediaBlocking enables request interception to block media resources.
// This reduces bandwidth and speeds up page loads by blocking images, stylesheets, fonts, and media.
// Returns a cleanup function that should be deferred.
// The cleanup function ensures the router goroutine exits cleanly with a timeout.
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

	// Track the router goroutine for proper cleanup
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Add panic recovery to prevent goroutine panic from crashing the process
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("Recovered from panic in media blocking router")
			}
		}()
		router.Run()
	}()

	return func() {
		// Stop the router - this signals the goroutine to exit
		if err := router.Stop(); err != nil {
			log.Debug().Err(err).Msg("Error stopping media blocking router")
		}

		// Wait for the goroutine to exit with a timeout
		// Fix MEDIUM: Use time.NewTimer instead of time.After to prevent timer leak
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()

		select {
		case <-done:
			// Clean exit
		case <-timer.C:
			log.Warn().Msg("Media blocking goroutine did not exit cleanly within timeout")
		}
	}
}

// Solve navigates to a URL and attempts to solve any Cloudflare challenges.
// It returns the page content after challenge resolution.
//
// Fix #12: Timeout validation notes:
//   - Zero or negative timeout is rejected with an error (prevents infinite waits)
//   - Timeouts under 1 second are adjusted to 1 second with a warning (prevents
//     unrealistic timeouts that would fail before the browser could even navigate)
//   - The timeout should be set appropriately at the handler layer based on config
//     (DefaultTimeout/MaxTimeout); this validation is a safety net
//
// Fix #24: Includes panic recovery to prevent crashes from browser-level panics.
func (s *Solver) Solve(ctx context.Context, opts *SolveOptions) (result *Result, err error) {
	// Fix #24: Panic recovery to catch browser-level panics
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Interface("panic", r).
				Str("url", opts.URL).
				Msg("Panic recovered in Solve")
			err = fmt.Errorf("unexpected error during solve: %v", r)
		}
	}()
	// Validate timeout: reject invalid values
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive, got %v", opts.Timeout)
	}

	// Ensure minimum timeout of 1 second for realistic operation
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

	// Acquire browser - use dedicated browser for per-request proxy, pooled otherwise
	var browserInstance *rod.Browser
	var usePooledBrowser bool

	if opts.Proxy != nil && opts.Proxy.URL != "" {
		// Per-request proxy: spawn dedicated browser with this proxy
		// This browser is NOT pooled and will be closed after use
		// Use redacted proxy URL in logs to prevent credential exposure
		// Note: Intentionally not logging auth presence to prevent information disclosure
		log.Info().
			Str("proxy_url", security.RedactProxyURL(opts.Proxy.URL)).
			Msg("Spawning dedicated browser with per-request proxy")
		// Fix HIGH: Use separate variable name to avoid shadowing the outer 'err'
		// which is used by panic recovery
		var spawnErr error
		browserInstance, spawnErr = s.pool.SpawnWithProxy(ctx, opts.Proxy.URL)
		if spawnErr != nil {
			return nil, fmt.Errorf("failed to spawn browser with proxy: %w", spawnErr)
		}
		defer func() {
			// Fix HIGH: Use explicit variable name to avoid shadowing outer 'err'
			if closeErr := browserInstance.Close(); closeErr != nil {
				log.Warn().Err(closeErr).Msg("failed to close dedicated browser")
			}
		}()
		usePooledBrowser = false
	} else {
		// No per-request proxy: use pooled browser (may have default proxy from config)
		log.Debug().Msg("Using pooled browser (no per-request proxy specified)")
		// Fix HIGH: Use separate variable name to avoid shadowing the outer 'err'
		// which is used by panic recovery
		var acquireErr error
		browserInstance, acquireErr = s.pool.Acquire(ctx)
		if acquireErr != nil {
			return nil, types.NewPoolAcquireError("failed to acquire browser", acquireErr)
		}
		defer s.pool.Release(browserInstance)
		usePooledBrowser = true
	}

	_ = usePooledBrowser // Used for logging/debugging if needed

	// Create timeout context for the solve operation
	solveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var page *rod.Page

	// For POST requests, we need a special approach because stealth scripts
	// conflict with form creation JavaScript. We use a regular page and
	// apply stealth manually after the POST navigation.
	if opts.IsPost && opts.PostData != "" {
		// Fix 2.10: Use stealth.Page for POST requests too - apply stealth before navigation
		// The previous concern about conflicts was resolved by proper ordering
		page, err = stealth.Page(browserInstance)
		if err != nil {
			return nil, fmt.Errorf("failed to create stealth page for POST: %w", err)
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

		// Fix #13: Use helper for proxy setup to reduce duplication
		proxyCleanup, err := setupProxyAuth(solveCtx, page, opts.Proxy)
		if err != nil {
			return nil, err
		}
		defer proxyCleanup()

		// Set cookies before navigation
		if len(opts.Cookies) > 0 {
			if err := s.setCookies(page, opts.Cookies, opts.URL); err != nil {
				log.Warn().Err(err).Msg("Failed to set cookies")
			}
		}

		// Set up network capture BEFORE navigation to capture response events
		networkCapture, networkCleanup, err := setupNetworkCapture(solveCtx, page)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to setup network capture, using defaults")
		}
		defer networkCleanup()

		// Dispatch POST based on content type
		if opts.ContentType == types.ContentTypeJSON {
			// JSON POST via Fetch API
			if err := s.navigatePostJSON(page.Context(solveCtx), opts.URL, opts.PostData, opts.Headers); err != nil {
				return nil, err
			}
		} else {
			// Form POST (default, backward compatible)
			if err := s.navigatePost(page.Context(solveCtx), opts.URL, opts.PostData); err != nil {
				return nil, err
			}
		}

		// Wait for initial load
		if err := page.Context(solveCtx).WaitLoad(); err != nil {
			log.Warn().Err(err).Msg("WaitLoad failed, continuing anyway")
		}

		// Main solve loop with DNS pinning
		return s.solveLoop(solveCtx, page, opts.URL, opts.Screenshot, opts.ExpectedIP, opts.TabsTillVerify, opts.SkipResponseValidation, networkCapture)
	}

	// GET request path
	// For GET requests, use stealth page
	page, err = stealth.Page(browserInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create stealth page: %w", err)
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

	// Fix #13: Use helper for proxy setup to reduce duplication
	proxyCleanup, err := setupProxyAuth(solveCtx, page, opts.Proxy)
	if err != nil {
		return nil, err
	}
	defer proxyCleanup()

	// Set cookies before navigation
	if len(opts.Cookies) > 0 {
		if err := s.setCookies(page, opts.Cookies, opts.URL); err != nil {
			log.Warn().Err(err).Msg("Failed to set cookies")
		}
	}

	// Set up network capture BEFORE navigation to capture response events
	networkCapture, networkCleanup, err := setupNetworkCapture(solveCtx, page)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to setup network capture, using defaults")
	}
	defer networkCleanup()

	// Set custom headers before navigation (for GET requests)
	if len(opts.Headers) > 0 {
		if err := s.setCustomHeaders(page, opts.Headers); err != nil {
			log.Warn().Err(err).Msg("Failed to set custom headers")
		}
	}

	// Regular GET request
	// Fix #7: Wrap navigation error with context for better debugging
	// Fix 2.6: Check context before navigation to fail fast
	if solveCtx.Err() != nil {
		return nil, fmt.Errorf("context canceled before navigation: %w", solveCtx.Err())
	}
	if err := page.Context(solveCtx).Navigate(opts.URL); err != nil {
		// Fix 2.6: Check if context was canceled to provide better error message
		if solveCtx.Err() != nil {
			return nil, fmt.Errorf("navigation timed out for %s: %w", opts.URL, solveCtx.Err())
		}
		return nil, fmt.Errorf("failed to navigate to %s: %w", opts.URL, err)
	}

	// Wait for initial load
	if err := page.Context(solveCtx).WaitLoad(); err != nil {
		log.Warn().Err(err).Msg("WaitLoad failed, continuing anyway")
	}

	// Main solve loop with DNS pinning
	result, err = s.solveLoop(solveCtx, page, opts.URL, opts.Screenshot, opts.ExpectedIP, opts.TabsTillVerify, opts.SkipResponseValidation, networkCapture)
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
	parsedURL, err := neturl.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("failed to parse cookie URL: %w", err)
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
	parsedURL, err := neturl.Parse(targetURL)
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
		return fmt.Errorf("context canceled during POST navigation: %w", page.GetContext().Err())
	}

	// Build form fields JavaScript
	fieldsJS, err := s.buildFormFieldsJS(postData)
	if err != nil {
		return fmt.Errorf("failed to build form fields: %w", err)
	}

	// Fix #14: Use JSON.Marshal for proper URL escaping instead of manual escaping.
	// This safely handles all special characters including quotes, backslashes,
	// newlines, unicode, and potential injection attempts.
	targetURLJSON, err := json.Marshal(targetURL)
	if err != nil {
		return fmt.Errorf("failed to encode target URL: %w", err)
	}

	// Use Runtime.evaluate directly via CDP to avoid Rod's wrapper
	// The URL is now a JSON string which includes quotes, so use it directly
	evalResult, err := proto.RuntimeEvaluate{
		Expression: fmt.Sprintf(`
			(function() {
				var form = document.createElement('form');
				form.method = 'POST';
				form.action = %s;
				form.style.display = 'none';
				%s
				document.body.appendChild(form);
				form.submit();
				return 'submitted';
			})()
		`, targetURLJSON, fieldsJS),
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
// Returns an error if any field fails to encode.
func (s *Solver) buildFormFieldsJS(postData string) (string, error) {
	if postData == "" {
		return "", nil
	}

	var builder strings.Builder
	pairs := strings.Split(postData, "&")
	for i, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			// URL decode the key and value
			key, err := neturl.QueryUnescape(parts[0])
			if err != nil {
				return "", fmt.Errorf("failed to decode form key %q: %w", parts[0], err)
			}
			value, err := neturl.QueryUnescape(parts[1])
			if err != nil {
				return "", fmt.Errorf("failed to decode form value for key %q: %w", key, err)
			}

			// Use JSON encoding for proper escaping of all special characters
			// This safely handles quotes, backslashes, newlines, unicode, and script tags
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return "", fmt.Errorf("failed to JSON encode form key %q: %w", key, err)
			}
			valueJSON, err := json.Marshal(value)
			if err != nil {
				return "", fmt.Errorf("failed to JSON encode form value for key %q: %w", key, err)
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
	return builder.String(), nil
}

// navigatePostJSON performs a POST request with JSON body using the Fetch API.
// This is used when contentType is "application/json".
func (s *Solver) navigatePostJSON(page *rod.Page, targetURL string, jsonData string, headers map[string]string) error {
	log.Debug().
		Str("url", targetURL).
		Int("json_data_len", len(jsonData)).
		Int("headers_count", len(headers)).
		Msg("Performing JSON POST request via Fetch API")

	// Parse the URL to get the base domain
	parsedURL, err := neturl.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Navigate to the target domain first to establish proper page context
	baseURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)
	if err := page.Navigate(baseURL); err != nil {
		return fmt.Errorf("failed to navigate to base URL: %w", err)
	}

	// Wait for page to be ready
	if err := page.WaitLoad(); err != nil {
		log.Debug().Err(err).Msg("WaitLoad on base URL failed")
	}

	// Give the page time to fully initialize
	if !sleepWithContext(page.GetContext(), 500*time.Millisecond) {
		return fmt.Errorf("context canceled during JSON POST navigation: %w", page.GetContext().Err())
	}

	// Build headers object JavaScript
	headersJS := s.buildHeadersJS(headers)

	// Safely encode the target URL and JSON data
	targetURLJSON, err := json.Marshal(targetURL)
	if err != nil {
		return fmt.Errorf("failed to encode target URL: %w", err)
	}

	// The jsonData is already a JSON string, but we need to escape it for embedding in JS
	jsonDataJS, err := json.Marshal(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encode JSON data: %w", err)
	}

	// Use Fetch API to perform the JSON POST request
	evalResult, err := proto.RuntimeEvaluate{
		Expression: fmt.Sprintf(`
			(async function() {
				try {
					var headers = new Headers({
						'Content-Type': 'application/json'
					});
					%s

					var response = await fetch(%s, {
						method: 'POST',
						headers: headers,
						body: %s,
						credentials: 'include'
					});

					var contentType = response.headers.get('content-type') || '';
					var text = await response.text();

					// Write the response to the document
					document.open();
					document.write(text);
					document.close();

					return {
						status: response.status,
						contentType: contentType,
						success: true
					};
				} catch(e) {
					return {
						success: false,
						error: e.message
					};
				}
			})()
		`, headersJS, targetURLJSON, jsonDataJS),
		AwaitPromise:  true,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		return fmt.Errorf("failed to execute JSON POST fetch: %w", err)
	}

	if evalResult.ExceptionDetails != nil {
		return fmt.Errorf("fetch exception: %s", evalResult.ExceptionDetails.Text)
	}

	// Parse the result to check for errors
	if evalResult.Result.Type == proto.RuntimeRemoteObjectTypeObject {
		jsonStr := evalResult.Result.Value.String()
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			if success, ok := result["success"].(bool); ok && !success {
				if errMsg, ok := result["error"].(string); ok {
					return fmt.Errorf("fetch failed: %s", errMsg)
				}
				return fmt.Errorf("fetch failed with unknown error")
			}
			if status, ok := result["status"].(float64); ok {
				log.Debug().Int("status", int(status)).Msg("JSON POST completed")
			}
		}
	}

	// Wait for the document to stabilize
	if err := page.WaitLoad(); err != nil {
		log.Warn().Err(err).Msg("WaitLoad after JSON POST failed, continuing anyway")
	}

	return nil
}

// buildHeadersJS generates JavaScript code to add custom headers to a Headers object.
func (s *Solver) buildHeadersJS(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}

	var builder strings.Builder
	for name, value := range headers {
		// Safely encode header name and value
		nameJSON, err := json.Marshal(name)
		if err != nil {
			log.Warn().Err(err).Str("header", name).Msg("Failed to encode header name")
			continue
		}
		valueJSON, err := json.Marshal(value)
		if err != nil {
			log.Warn().Err(err).Str("header", name).Msg("Failed to encode header value")
			continue
		}
		builder.WriteString(fmt.Sprintf("headers.set(%s, %s);\n", nameJSON, valueJSON))
	}
	return builder.String()
}

// setCustomHeaders sets custom HTTP headers on the page using CDP.
// These headers will be sent with subsequent requests.
func (s *Solver) setCustomHeaders(page *rod.Page, headers map[string]string) error {
	if len(headers) == 0 {
		return nil
	}

	log.Debug().Int("count", len(headers)).Msg("Setting custom HTTP headers via CDP")

	// Convert to proto.NetworkHeaders
	// NetworkHeaders is map[string]gson.JSON, so we use gson.New to convert strings
	networkHeaders := make(proto.NetworkHeaders, len(headers))
	for name, value := range headers {
		networkHeaders[name] = gson.New(value)
	}

	// Use Network.setExtraHTTPHeaders to inject custom headers
	err := proto.NetworkSetExtraHTTPHeaders{
		Headers: networkHeaders,
	}.Call(page)

	if err != nil {
		return fmt.Errorf("failed to set custom headers: %w", err)
	}

	return nil
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
	".cf-turnstile", // Turnstile widget class (used by nowsecure.nl and others)
	"#cf-wrapper",
	"#challenge-running",
	"#challenge-stage",
	"#cf-spinner-please-wait",
	"#cf-spinner-redirecting",
}

// solveLoop repeatedly checks for and attempts to solve challenges.
// Uses the same approach as Python FlareSolverr: check title and selectors.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - page: The browser page
//   - url: The original request URL
//   - captureScreenshot: Whether to capture a screenshot
//   - expectedIP: The IP resolved during initial validation for DNS pinning (nil to skip)
//   - tabsTillVerify: Number of Tab presses to reach Turnstile checkbox (0 uses default of 10)
//   - skipValidation: If true, skip response URL validation (for testing only)
//   - networkCapture: Optional network capture for real HTTP status codes and headers (may be nil)
func (s *Solver) solveLoop(ctx context.Context, page *rod.Page, url string, captureScreenshot bool, expectedIP net.IP, tabsTillVerify int, skipValidation bool, networkCapture *NetworkCapture) (*Result, error) {
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
		// Check context at the start of each iteration to fail fast
		// This is the primary cancellation check point
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
			return s.buildResult(page, url, captureScreenshot, expectedIP, skipValidation, networkCapture)
		}

		// Check for access denied
		html, err := page.HTML()
		if err != nil {
			// Fix: Return error if HTML retrieval fails since we can't determine page state
			log.Debug().Err(err).Msg("Failed to get page HTML for challenge detection")
			return nil, fmt.Errorf("failed to get page HTML: %w", err)
		}
		if html != "" && s.detectChallenge(html) == ChallengeAccessDenied {
			return nil, types.NewAccessDeniedError(url)
		}

		// If Turnstile is present, try to solve it
		// Check for both #turnstile-wrapper (ID) and .cf-turnstile (class)
		if challengeSelector == "#turnstile-wrapper" || challengeSelector == ".cf-turnstile" {
			log.Debug().Str("selector", challengeSelector).Msg("Turnstile detected, attempting to solve...")
			if err := s.solveTurnstile(ctx, page, tabsTillVerify); err != nil {
				// Fix: Log but continue - Turnstile solve is best-effort, the loop will
				// check again and return error if challenge persists past timeout
				log.Warn().Err(err).Msg("Turnstile solve attempt failed, will retry")
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
// Uses shared timeout budget across all selector checks to prevent stacked timeouts.
// Fix: Share timeout budget across selectors instead of giving each one a full 2 seconds.
func (s *Solver) findChallengeSelector(page *rod.Page) string {
	// Calculate timeout budget: use page's context deadline if available, otherwise default
	ctx := page.GetContext()
	totalTimeout := 5 * time.Second // Default total budget for all selectors
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < totalTimeout {
			totalTimeout = remaining
		}
	}

	// Distribute timeout budget across selectors (minimum 100ms each)
	perSelectorTimeout := totalTimeout / time.Duration(len(challengeSelectors)+1)
	if perSelectorTimeout < 100*time.Millisecond {
		perSelectorTimeout = 100 * time.Millisecond
	}

	for _, selector := range challengeSelectors {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ""
		default:
		}

		has, _, _ := page.Timeout(perSelectorTimeout).Has(selector)
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
// Uses multiple approaches in order of preference (detection risk):
// 1. Shadow DOM traversal (CDP-native, low detection risk)
// 2. Keyboard navigation (natural behavior, low detection risk)
// 3. Direct widget click (medium detection risk)
// 4. iframe click (medium detection risk)
// 5. Positional click (last resort, medium detection risk)
//
// Properly releases DOM element references to prevent memory leaks.
//
// Parameters:
//   - tabsTillVerify: Number of Tab presses to reach the Turnstile checkbox (0 uses default of 10)
func (s *Solver) solveTurnstile(ctx context.Context, page *rod.Page, tabsTillVerify int) error {
	log.Debug().Msg("Attempting to solve Turnstile challenge")

	// Method 1: Try CDP-native shadow DOM traversal first (lowest detection risk)
	// This uses Rod's ShadowRoot() which accesses closed shadow roots via CDP debugger API
	if err := s.solveTurnstileShadow(ctx, page); err == nil {
		log.Debug().Msg("Turnstile shadow DOM traversal attempted")
	}

	// Fix #6: Pass context to all Turnstile methods
	// Method 2: Try keyboard navigation (low fingerprinting, natural user behavior)
	if err := s.solveTurnstileKeyboard(ctx, page, tabsTillVerify); err == nil {
		log.Debug().Msg("Turnstile keyboard navigation attempted")
	}

	// Method 3: Try direct widget click as fallback (for visible Turnstile widgets)
	if err := s.solveTurnstileWidget(ctx, page); err == nil {
		log.Debug().Msg("Turnstile widget click attempted")
	}

	// Method 4: Try iframe click (for challenges.cloudflare.com iframe)
	if err := s.solveTurnstileClick(ctx, page); err == nil {
		log.Debug().Msg("Turnstile iframe click attempted")
	}

	// Method 5: Try positional click as last resort
	// This clicks at a fixed offset from the Turnstile container bounds
	if err := s.solveTurnstilePositional(ctx, page); err == nil {
		log.Debug().Msg("Turnstile positional click attempted")
	}

	// Don't return error - the solveLoop will check if challenge is still present
	return nil
}

// solveTurnstileShadow uses CDP-native shadow root traversal to find and click
// the Turnstile checkbox. This method works with closed shadow roots because
// Rod's ShadowRoot() uses CDP's DOM.describeNode with debugger-level access.
//
// Detection risk: LOW - uses debugger API, no JavaScript modification
func (s *Solver) solveTurnstileShadow(ctx context.Context, page *rod.Page) error {
	log.Debug().Msg("Trying CDP-native shadow DOM traversal for Turnstile")

	traverser := NewShadowRootTraverser(page)

	// Try to find and click the checkbox via shadow DOM
	if err := traverser.ClickCheckbox(ctx); err != nil {
		log.Debug().Err(err).Msg("Shadow DOM checkbox click failed")
		return fmt.Errorf("shadow DOM click failed: %w", err)
	}

	log.Info().Msg("Clicked Turnstile checkbox via shadow DOM traversal")

	// Wait for the click to register
	if !sleepWithContext(ctx, 1*time.Second) {
		return fmt.Errorf("context canceled after shadow DOM click")
	}

	return nil
}

// solveTurnstilePositional clicks at a calculated position based on the
// Turnstile container bounds. This is a last resort when other methods fail.
// The checkbox is typically at offset (20, 20) from the container's top-left.
//
// Detection risk: MEDIUM - coordinates may reveal automation patterns
func (s *Solver) solveTurnstilePositional(ctx context.Context, page *rod.Page) error {
	log.Debug().Msg("Trying positional click for Turnstile")

	traverser := NewShadowRootTraverser(page)

	// Get the Turnstile container bounds
	bounds, err := traverser.GetTurnstileContainerBounds(ctx)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get Turnstile container bounds")
		return fmt.Errorf("failed to get container bounds: %w", err)
	}

	// Calculate checkbox position (typically offset 20-25 pixels from top-left)
	// The checkbox is usually near the left edge, vertically centered
	checkboxOffsetX := 20.0
	checkboxOffsetY := bounds.Height / 2 // Center vertically

	clickX := bounds.X + checkboxOffsetX
	clickY := bounds.Y + checkboxOffsetY

	log.Debug().
		Float64("container_x", bounds.X).
		Float64("container_y", bounds.Y).
		Float64("container_width", bounds.Width).
		Float64("container_height", bounds.Height).
		Float64("click_x", clickX).
		Float64("click_y", clickY).
		Msg("Calculated positional click coordinates")

	// Move to position and click
	centerX := int(clickX)
	centerY := int(clickY)
	if err := page.Mouse.MoveTo(proto.NewPoint(clickX, clickY)); err != nil {
		log.Debug().Err(err).Msg("Failed to move mouse for positional click")
		return fmt.Errorf("failed to move mouse to (%d, %d): %w", centerX, centerY, err)
	}

	if err := page.Mouse.Click(proto.InputMouseButtonLeft, 1); err != nil {
		log.Debug().Err(err).Msg("Failed positional click")
		return fmt.Errorf("failed to click at (%d, %d): %w", centerX, centerY, err)
	}

	log.Info().
		Float64("x", clickX).
		Float64("y", clickY).
		Msg("Performed positional click on Turnstile")

	// Wait for the click to register
	if !sleepWithContext(ctx, 1*time.Second) {
		return fmt.Errorf("context canceled after positional click")
	}

	return nil
}

// solveTurnstileWidget attempts to click directly on the Turnstile widget element.
// Fix #6: Accepts context for proper timeout/cancellation propagation.
func (s *Solver) solveTurnstileWidget(ctx context.Context, page *rod.Page) error {
	// Check context before starting
	if ctx.Err() != nil {
		return ctx.Err()
	}
	log.Debug().Msg("Trying direct widget click for Turnstile")

	// Try clicking on .cf-turnstile widget or its checkbox
	widgetSelectors := []string{
		".cf-turnstile iframe",
		".cf-turnstile",
		"#turnstile-wrapper iframe",
		"#turnstile-wrapper",
		"[data-sitekey] iframe",
		"[data-sitekey]",
	}

	for _, selector := range widgetSelectors {
		// Use Has() to check if element exists without waiting
		has, _, _ := page.Has(selector)
		if !has {
			continue
		}

		// Use timeout to prevent hanging
		element, err := page.Timeout(2 * time.Second).Element(selector)
		if err != nil {
			log.Debug().Str("selector", selector).Err(err).Msg("Failed to get element")
			continue
		}

		// Try to get the element's bounding box and click in the center
		box, err := element.Shape()
		if err == nil && box != nil && len(box.Quads) > 0 {
			// Get center of the element
			quad := box.Quads[0]
			x := (quad[0] + quad[2] + quad[4] + quad[6]) / 4
			y := (quad[1] + quad[3] + quad[5] + quad[7]) / 4

			log.Debug().Str("selector", selector).Float64("x", x).Float64("y", y).Msg("Clicking Turnstile widget")

			// Move to position and click
			if moveErr := page.Mouse.MoveTo(proto.NewPoint(x, y)); moveErr != nil {
				log.Debug().Err(moveErr).Msg("Failed to move mouse")
				continue
			}
			if clickErr := page.Mouse.Click(proto.InputMouseButtonLeft, 1); clickErr == nil {
				log.Info().Str("selector", selector).Msg("Clicked Turnstile widget")
			}
		}

		if err := element.Release(); err != nil {
			log.Debug().Err(err).Str("selector", selector).Msg("Error releasing DOM element")
		}
	}

	return nil
}

// solveTurnstileKeyboard uses keyboard navigation to solve Turnstile.
// This matches Python FlareSolverr v3.3.22's click_verify() function which uses Tab+Enter.
// Using keyboard navigation instead of mouse clicks avoids fingerprinting detection.
//
// Fix #6: Accepts context for proper timeout/cancellation propagation.
//
// Parameters:
//   - ctx: Context for cancellation
//   - tabsTillVerify: Number of Tab presses to reach the Turnstile checkbox (0 uses default of 10)
func (s *Solver) solveTurnstileKeyboard(ctx context.Context, page *rod.Page, tabsTillVerify int) error {
	// Use default of 10 tabs if not specified (matches Python FlareSolverr default)
	tabCount := tabsTillVerify
	if tabCount <= 0 {
		tabCount = 10
	}

	log.Debug().Int("tab_count", tabCount).Msg("Trying keyboard navigation for Turnstile")

	// Wait a moment for Turnstile to fully load, but respect context (Bug 2)
	if !sleepWithContext(ctx, 2*time.Second) {
		return fmt.Errorf("context canceled during Turnstile solve")
	}

	keyboard := page.Keyboard

	// Tab through elements to reach the Turnstile checkbox
	for i := 0; i < tabCount; i++ {
		if err := keyboard.Press(input.Tab); err != nil {
			log.Debug().Err(err).Int("tab", i).Msg("Tab press failed")
			continue
		}
		// Context-aware sleep (Bug 2)
		if !sleepWithContext(ctx, 200*time.Millisecond) {
			return fmt.Errorf("context canceled during Turnstile solve")
		}
	}

	// Press Enter to activate the checkbox (matches Python v3.3.22)
	if err := keyboard.Press(input.Enter); err != nil {
		log.Debug().Err(err).Msg("Enter press failed")
		return fmt.Errorf("failed to press Enter key: %w", err)
	}

	log.Info().Msg("Sent keyboard Tab+Enter for Turnstile")

	// Wait a moment for the action to register, but respect context (Bug 2)
	if !sleepWithContext(ctx, 1*time.Second) {
		return fmt.Errorf("context canceled during Turnstile solve")
	}

	// Try to find and activate "Verify you are human" button using keyboard
	// Use keyboard Enter instead of mouse click to avoid fingerprinting
	if btn, err := page.Timeout(2 * time.Second).Element("//button[contains(text(),'Verify')]"); err == nil {
		// Always defer element release to prevent memory leaks
		defer func() {
			if releaseErr := btn.Release(); releaseErr != nil {
				log.Debug().Err(releaseErr).Msg("Error releasing Verify button element")
			}
		}()
		if focusErr := btn.Focus(); focusErr == nil {
			if enterErr := keyboard.Press(input.Enter); enterErr == nil {
				log.Info().Msg("Pressed Enter on Verify button")
			}
		}
	}

	return nil
}

// solveTurnstileClick attempts to directly click the Turnstile checkbox in iframe.
// Fix #6: Accepts context for proper timeout/cancellation propagation.
func (s *Solver) solveTurnstileClick(ctx context.Context, page *rod.Page) error {
	// Check context before starting
	if ctx.Err() != nil {
		return ctx.Err()
	}
	log.Debug().Msg("Trying direct iframe click for Turnstile")

	sel := selectors.Get()

	// Find all iframes on the page with timeout to prevent hanging
	iframes, err := page.Timeout(5 * time.Second).Elements("iframe")
	if err != nil {
		return fmt.Errorf("failed to get iframes: %w", err)
	}

	// CRITICAL: Release all iframes when done to prevent memory leak
	defer func() {
		for _, iframe := range iframes {
			if err := iframe.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release iframe element")
			}
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
				if err := element.Release(); err != nil {
					log.Debug().Err(err).Str("selector", selector).Msg("Error releasing Turnstile iframe element")
				}

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

// Maximum number of cookies to extract to prevent resource exhaustion
const maxExtractedCookies = 100

// Maximum screenshot size to prevent memory exhaustion (5MB)
const maxScreenshotSize = 5 * 1024 * 1024

// Maximum number of localStorage/sessionStorage items to extract
const maxStorageItems = 100

// Maximum total size of localStorage/sessionStorage data (1MB)
const maxStorageSize = 1 * 1024 * 1024

// Maximum number of response headers to capture
const maxResponseHeaders = 100

// Maximum cookie value size (4KB per RFC 6265)
const maxCookieValueSize = 4 * 1024

// validateResponseURL validates the current page URL to detect DNS rebinding attacks.
// This should be called after navigation to ensure we haven't been redirected to a blocked IP.
//
// Parameters:
//   - page: The browser page to validate
//   - expectedIP: The IP that was resolved during initial validation (nil to skip pinning)
//   - skipValidation: If true, skip all validation (for testing only - DO NOT use in production)
//
// DNS Pinning: If expectedIP is provided, the function verifies that the response URL
// still resolves to the same IP. This prevents DNS rebinding attacks where an attacker:
//  1. Initially resolves their domain to a safe IP (passes validation)
//  2. Changes DNS to point to an internal IP before the browser navigates
//  3. Browser ends up accessing internal resources
func (s *Solver) validateResponseURL(page *rod.Page, expectedIP net.IP, skipValidation bool) error {
	// Skip validation if requested (for testing only)
	if skipValidation {
		return nil
	}

	info, err := page.Info()
	if err != nil {
		// Can't get page info - allow to continue
		log.Debug().Err(err).Msg("Could not get page info for URL validation")
		return nil
	}

	if info.URL == "" || info.URL == "about:blank" {
		return nil
	}

	// Use DNS pinning validation if we have an expected IP
	if expectedIP != nil {
		if err := security.ValidateURLWithPinnedIP(info.URL, expectedIP); err != nil {
			log.Warn().
				Str("url", info.URL).
				Str("expected_ip", expectedIP.String()).
				Err(err).
				Msg("Response URL failed DNS pinning validation (possible DNS rebinding attack)")
			return fmt.Errorf("DNS rebinding detected: %w", err)
		}
		log.Debug().
			Str("url", info.URL).
			Str("expected_ip", expectedIP.String()).
			Msg("Response URL passed DNS pinning validation")
		return nil
	}

	// Fallback: Re-validate the response URL without pinning
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
//
// Parameters:
//   - page: The browser page
//   - url: The original request URL
//   - captureScreenshot: Whether to capture a screenshot
//   - expectedIP: The IP resolved during initial validation for DNS pinning (nil to skip)
//   - skipValidation: If true, skip response URL validation (for testing only)
//   - networkCapture: Optional network capture for real HTTP status codes and headers (may be nil)
func (s *Solver) buildResult(page *rod.Page, url string, captureScreenshot bool, expectedIP net.IP, skipValidation bool, networkCapture *NetworkCapture) (*Result, error) {
	// Validate response URL to detect DNS rebinding attacks
	if err := s.validateResponseURL(page, expectedIP, skipValidation); err != nil {
		return nil, err
	}

	html, err := page.HTML()
	if err != nil {
		return nil, err
	}
	return s.buildResultWithHTML(page, url, html, captureScreenshot, networkCapture)
}

// buildResultWithHTML constructs the result using pre-fetched HTML.
// This avoids redundant HTML fetching when HTML is already available.
//
// Parameters:
//   - page: The browser page
//   - url: The original request URL
//   - html: Pre-fetched HTML content
//   - captureScreenshot: Whether to capture a screenshot
//   - networkCapture: Optional network capture for real HTTP status codes and headers (may be nil)
func (s *Solver) buildResultWithHTML(page *rod.Page, url string, html string, captureScreenshot bool, networkCapture *NetworkCapture) (*Result, error) {
	// Fix #15: Track if HTML was truncated
	htmlTruncated := false

	// Limit response size to prevent memory exhaustion
	if len(html) > maxResponseSize {
		log.Warn().
			Int("size", len(html)).
			Int("max", maxResponseSize).
			Msg("Response truncated due to size limit")
		html = html[:maxResponseSize]
		htmlTruncated = true
	}

	var cookieError string
	// Use Network.getAllCookies to get ALL cookies regardless of domain
	// This is the same method Python FlareSolverr uses via Selenium's driver.get_cookies()
	var cookies []*proto.NetworkCookie
	allCookiesResult, err := proto.NetworkGetAllCookies{}.Call(page)
	if err != nil {
		// Chrome 114+ returns partitionKey as string which causes unmarshal warning
		// Cookies are still returned successfully, so only log at debug level for this case
		if strings.Contains(err.Error(), "partitionKey") {
			log.Debug().Msg("Cookie partitionKey field type mismatch (harmless)")
			// Still try to access cookies even with the warning
			if allCookiesResult != nil {
				cookies = allCookiesResult.Cookies
			}
		} else {
			log.Warn().Err(err).Msg("Failed to get all cookies")
			cookieError = err.Error()
		}
	} else if allCookiesResult != nil {
		cookies = allCookiesResult.Cookies
	}

	// Enforce cookie count limit to prevent resource exhaustion
	if len(cookies) > maxExtractedCookies {
		log.Warn().
			Int("count", len(cookies)).
			Int("max", maxExtractedCookies).
			Msg("Cookie count exceeds limit, truncating")
		cookies = cookies[:maxExtractedCookies]
	}

	// Fix: Enforce per-cookie value size limit to prevent memory exhaustion
	for i, cookie := range cookies {
		if len(cookie.Value) > maxCookieValueSize {
			log.Warn().
				Str("cookie_name", cookie.Name).
				Int("value_size", len(cookie.Value)).
				Int("max_size", maxCookieValueSize).
				Msg("Cookie value exceeds maximum size, truncating")
			// Create a truncated copy to avoid modifying the original
			truncatedCookie := *cookie
			truncatedCookie.Value = cookie.Value[:maxCookieValueSize]
			cookies[i] = &truncatedCookie
		}
	}

	log.Debug().Int("cookie_count", len(cookies)).Msg("Retrieved all cookies via Network.getAllCookies")

	// Get current URL (may have been redirected)
	currentURL := url
	if info, err := page.Info(); err == nil && info.URL != "" {
		currentURL = info.URL
	}

	// Extract Turnstile token if present
	turnstileToken := s.extractTurnstileToken(page)
	if turnstileToken != "" {
		log.Debug().Str("token_prefix", turnstileToken[:min(20, len(turnstileToken))]).Msg("Extracted Turnstile token")
	}

	// Extract localStorage and sessionStorage for debugging
	localStorage := s.extractLocalStorage(page)
	sessionStorage := s.extractSessionStorage(page)

	// Get status code and headers from network capture, or use DOM extraction as fallback
	statusCode := 200 // Default fallback
	var responseHeaders map[string]string
	if networkCapture != nil {
		capturedStatus := networkCapture.StatusCode()
		if capturedStatus > 0 {
			statusCode = capturedStatus
		}
		capturedHeaders := networkCapture.Headers()
		if len(capturedHeaders) > 0 {
			responseHeaders = capturedHeaders
			log.Debug().
				Int("status_code", statusCode).
				Int("header_count", len(responseHeaders)).
				Msg("Using captured network response data")
		}
	}

	// Fall back to DOM extraction if network capture didn't get headers
	if len(responseHeaders) == 0 {
		responseHeaders = s.extractResponseHeaders(page)
		log.Debug().Msg("Using DOM-extracted response headers (fallback)")
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
		Bool("html_truncated", htmlTruncated).
		Bool("has_turnstile_token", turnstileToken != "").
		Bool("has_screenshot", screenshotBase64 != "").
		Int("localStorage_count", len(localStorage)).
		Int("sessionStorage_count", len(sessionStorage)).
		Msg("Solve completed successfully")

	return &Result{
		Success:         true,
		StatusCode:      statusCode, // Use captured status code from network response
		HTML:            html,
		HTMLTruncated:   htmlTruncated, // Fix #15: Include truncation flag
		Cookies:         cookies,
		CookieError:     cookieError, // Include cookie retrieval error if any
		UserAgent:       s.userAgent,
		URL:             currentURL,
		TurnstileToken:  turnstileToken,
		Screenshot:      screenshotBase64,
		LocalStorage:    localStorage,
		SessionStorage:  sessionStorage,
		ResponseHeaders: responseHeaders,
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

	// Use safe helper to prevent nil pointer panic
	return safeEvalResultString(result)
}

// extractLocalStorage extracts all localStorage key-value pairs from the page.
// Enforces limits on item count and total size to prevent resource exhaustion.
func (s *Solver) extractLocalStorage(page *rod.Page) map[string]string {
	result, err := proto.RuntimeEvaluate{
		Expression: `(function() {
			var data = {};
			try {
				for (var i = 0; i < localStorage.length; i++) {
					var key = localStorage.key(i);
					data[key] = localStorage.getItem(key);
				}
			} catch(e) {
				// localStorage might not be available
			}
			return JSON.stringify(data);
		})()`,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract localStorage")
		return nil
	}

	// Use safe helper to extract string value
	jsonStr := safeEvalResultString(result)
	if jsonStr == "" {
		return nil
	}

	// Check total size limit before parsing
	if len(jsonStr) > maxStorageSize {
		log.Warn().
			Int("size", len(jsonStr)).
			Int("max", maxStorageSize).
			Msg("localStorage data exceeds size limit, truncating")
		return nil
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		log.Debug().Err(err).Msg("Failed to parse localStorage JSON")
		return nil
	}

	// Enforce item count limit
	if len(data) > maxStorageItems {
		log.Warn().
			Int("count", len(data)).
			Int("max", maxStorageItems).
			Msg("localStorage item count exceeds limit, truncating")
		truncated := make(map[string]string, maxStorageItems)
		count := 0
		for k, v := range data {
			if count >= maxStorageItems {
				break
			}
			truncated[k] = v
			count++
		}
		data = truncated
	}

	if len(data) > 0 {
		log.Debug().Int("count", len(data)).Msg("Extracted localStorage items")
	}
	return data
}

// extractSessionStorage extracts all sessionStorage key-value pairs from the page.
// Enforces limits on item count and total size to prevent resource exhaustion.
func (s *Solver) extractSessionStorage(page *rod.Page) map[string]string {
	result, err := proto.RuntimeEvaluate{
		Expression: `(function() {
			var data = {};
			try {
				for (var i = 0; i < sessionStorage.length; i++) {
					var key = sessionStorage.key(i);
					data[key] = sessionStorage.getItem(key);
				}
			} catch(e) {
				// sessionStorage might not be available
			}
			return JSON.stringify(data);
		})()`,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract sessionStorage")
		return nil
	}

	// Use safe helper to extract string value
	jsonStr := safeEvalResultString(result)
	if jsonStr == "" {
		return nil
	}

	// Check total size limit before parsing
	if len(jsonStr) > maxStorageSize {
		log.Warn().
			Int("size", len(jsonStr)).
			Int("max", maxStorageSize).
			Msg("sessionStorage data exceeds size limit, truncating")
		return nil
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		log.Debug().Err(err).Msg("Failed to parse sessionStorage JSON")
		return nil
	}

	// Enforce item count limit
	if len(data) > maxStorageItems {
		log.Warn().
			Int("count", len(data)).
			Int("max", maxStorageItems).
			Msg("sessionStorage item count exceeds limit, truncating")
		truncated := make(map[string]string, maxStorageItems)
		count := 0
		for k, v := range data {
			if count >= maxStorageItems {
				break
			}
			truncated[k] = v
			count++
		}
		data = truncated
	}

	if len(data) > 0 {
		log.Debug().Int("count", len(data)).Msg("Extracted sessionStorage items")
	}
	return data
}

// extractResponseHeaders gets the response headers from the page's main document.
// Note: This uses the Performance API to get resource timing info, but headers
// are not directly accessible. For full headers, we'd need to intercept network requests.
// Enforces limits on header count to prevent resource exhaustion.
func (s *Solver) extractResponseHeaders(page *rod.Page) map[string]string {
	// Try to get headers from the document's response
	// This is limited - full header access requires network interception
	result, err := proto.RuntimeEvaluate{
		Expression: `(function() {
			var headers = {};
			try {
				// Check for any Cloudflare-specific meta tags or data
				var cfRay = document.querySelector('meta[name="cf-ray"]');
				if (cfRay) headers['cf-ray'] = cfRay.content;

				// Check for any server timing info
				var entries = performance.getEntriesByType('navigation');
				if (entries.length > 0) {
					var nav = entries[0];
					if (nav.serverTiming) {
						nav.serverTiming.forEach(function(t) {
							headers['server-timing-' + t.name] = t.description || String(t.duration);
						});
					}
				}

				// Check for Cloudflare challenge tokens in the page
				var cfChallenge = document.querySelector('[data-cf-challenge]');
				if (cfChallenge) headers['cf-challenge-present'] = 'true';

				// Check for any cf_ prefixed inputs (challenge forms)
				var cfInputs = document.querySelectorAll('input[name^="cf"]');
				if (cfInputs.length > 0) {
					headers['cf-inputs-count'] = String(cfInputs.length);
				}

				// Check document.cookie for cf_ cookies (visible ones)
				var cookieStr = document.cookie;
				if (cookieStr.indexOf('cf_') !== -1) {
					headers['cf-cookie-present'] = 'true';
				}

			} catch(e) {
				headers['extraction-error'] = e.message;
			}
			return JSON.stringify(headers);
		})()`,
		ReturnByValue: true,
	}.Call(page)

	if err != nil {
		log.Debug().Err(err).Msg("Failed to extract response headers")
		return nil
	}

	// Use safe helper to extract string value
	jsonStr := safeEvalResultString(result)
	if jsonStr == "" {
		return nil
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		log.Debug().Err(err).Msg("Failed to parse response headers JSON")
		return nil
	}

	// Enforce header count limit
	if len(data) > maxResponseHeaders {
		log.Warn().
			Int("count", len(data)).
			Int("max", maxResponseHeaders).
			Msg("Response header count exceeds limit, truncating")
		truncated := make(map[string]string, maxResponseHeaders)
		count := 0
		for k, v := range data {
			if count >= maxResponseHeaders {
				break
			}
			truncated[k] = v
			count++
		}
		data = truncated
	}

	return data
}

// captureScreenshot captures a PNG screenshot of the page.
// Returns an error if the screenshot exceeds the maximum size limit.
func (s *Solver) captureScreenshot(page *rod.Page) ([]byte, error) {
	// Use full page screenshot
	screenshot, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: nil, // PNG doesn't use quality
	})
	if err != nil {
		return nil, fmt.Errorf("screenshot capture failed: %w", err)
	}

	// Enforce size limit to prevent memory exhaustion
	if len(screenshot) > maxScreenshotSize {
		log.Warn().
			Int("size", len(screenshot)).
			Int("max", maxScreenshotSize).
			Msg("Screenshot exceeds maximum size limit, returning error")
		return nil, fmt.Errorf("screenshot size %d exceeds maximum limit of %d bytes", len(screenshot), maxScreenshotSize)
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

	// Apply stealth patches only to fresh/blank pages
	// On session reuse, the page already has content and stealth was already applied
	// Trying to re-apply stealth to a loaded page causes errors due to stale JS context
	pageInfo, _ := page.Info()
	if pageInfo == nil || pageInfo.URL == "" || pageInfo.URL == "about:blank" {
		if err := browser.ApplyStealthToPage(page); err != nil {
			log.Warn().Err(err).Msg("Failed to apply stealth patches")
		}
	} else {
		log.Debug().Str("url", pageInfo.URL).Msg("Skipping stealth on reused session page")
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

	// Set up network capture BEFORE navigation to capture response events
	networkCapture, networkCleanup, err := setupNetworkCapture(solveCtx, page)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to setup network capture, using defaults")
	}
	defer networkCleanup()

	// Navigate (GET or POST)
	// Use page.Context() inline to avoid reassigning the page variable
	if opts.IsPost && opts.PostData != "" {
		// Dispatch POST based on content type
		if opts.ContentType == types.ContentTypeJSON {
			// JSON POST via Fetch API
			if err := s.navigatePostJSON(page.Context(solveCtx), opts.URL, opts.PostData, opts.Headers); err != nil {
				return nil, err
			}
		} else {
			// Form POST (default, backward compatible)
			if err := s.navigatePost(page.Context(solveCtx), opts.URL, opts.PostData); err != nil {
				return nil, err
			}
		}
	} else {
		// Set custom headers before navigation (for GET requests)
		if len(opts.Headers) > 0 {
			if err := s.setCustomHeaders(page, opts.Headers); err != nil {
				log.Warn().Err(err).Msg("Failed to set custom headers")
			}
		}
		if err := page.Context(solveCtx).Navigate(opts.URL); err != nil {
			return nil, err
		}
	}

	// Wait for load
	if err := page.Context(solveCtx).WaitLoad(); err != nil {
		log.Warn().Err(err).Msg("WaitLoad failed, continuing anyway")
	}

	// Solve with DNS pinning
	result, err := s.solveLoop(solveCtx, page, opts.URL, opts.Screenshot, opts.ExpectedIP, opts.TabsTillVerify, opts.SkipResponseValidation, networkCapture)
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

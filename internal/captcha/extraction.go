// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	// extractionEvalTimeout bounds one extraction script or DOM snapshot.
	extractionEvalTimeout = 8 * time.Second

	// turnstileChallengeHost serves every Turnstile widget and challenge iframe.
	turnstileChallengeHost = "challenges.cloudflare.com"

	// Sitekey length bounds. Real Turnstile sitekeys are about 24 characters.
	minSitekeyLen = 11
	maxSitekeyLen = 100

	// recaptchaSitekeyLen is the fixed length of a reCAPTCHA sitekey ("6L...").
	recaptchaSitekeyLen = 40

	// maxWidgetCandidates bounds how many candidate elements a page may report.
	maxWidgetCandidates = 32

	// maxPierceNodes bounds the pierced DOM walk.
	maxPierceNodes = 50000
)

// TurnstileWidget is a Turnstile widget found in the page's DOM. Action and
// CData belong to the same element as the sitekey, never to some other element
// that happens to carry a data-action attribute.
type TurnstileWidget struct {
	SiteKey string `json:"sitekey"`
	Action  string `json:"action"`
	CData   string `json:"cdata"`
}

// widgetCandidate is one element (or script) the page reported as possibly
// describing a Turnstile widget. The page only collects; Go decides.
type widgetCandidate struct {
	TurnstileWidget
	// Source is "widget" (a .cf-turnstile element), "attribute" (some other
	// element with data-sitekey) or "script" (a turnstile.render() call).
	Source string `json:"source"`
	// Foreign is true when the element belongs to another captcha vendor's
	// widget (.h-captcha, .g-recaptcha).
	Foreign bool `json:"foreign"`
}

// turnstileWidgetJS collects candidate Turnstile widgets from the main frame.
// It reports every element with a data-sitekey, tagged with what it is, plus
// sitekeys passed literally to turnstile.render() in inline scripts.
const turnstileWidgetJS = `
(function() {
	var out = [];
	var max = %d;
	var els = document.querySelectorAll('[data-sitekey]');
	for (var i = 0; i < els.length && out.length < max; i++) {
		var el = els[i];
		var isWidget = el.classList.contains('cf-turnstile');
		out.push({
			sitekey: el.getAttribute('data-sitekey') || '',
			action: el.getAttribute('data-action') || '',
			cdata: el.getAttribute('data-cdata') || '',
			source: isWidget ? 'widget' : 'attribute',
			foreign: !isWidget && !!el.closest('.h-captcha, .g-recaptcha, [data-hcaptcha-widget-id]')
		});
	}
	var scripts = document.querySelectorAll('script:not([src])');
	for (var i = 0; i < scripts.length && out.length < max; i++) {
		var text = scripts[i].textContent || '';
		if (text.length > 200000) continue;
		var match = text.match(/turnstile\.render\([^)]{0,2000}?sitekey['"]?\s*:\s*['"]([0-9a-zA-Z_-]+)['"]/);
		if (match) out.push({ sitekey: match[1], action: '', cdata: '', source: 'script', foreign: false });
	}
	return JSON.stringify(out);
})()
`

// oopifSitekeyJS reports candidate sitekeys from inside a child frame: its own
// Turnstile elements, the URLs of its iframes, and anything the interceptor
// captured there. The URLs are parsed in Go.
const oopifSitekeyJS = `
(function() {
	var out = { keys: [], urls: [] };
	if (window.__cfChallengeParams && window.__cfChallengeParams.sitekey) {
		out.keys.push(window.__cfChallengeParams.sitekey);
	}
	var els = document.querySelectorAll('.cf-turnstile[data-sitekey]');
	for (var i = 0; i < els.length && out.keys.length < 8; i++) {
		out.keys.push(els[i].getAttribute('data-sitekey') || '');
	}
	var iframes = document.querySelectorAll('iframe[src]');
	for (var i = 0; i < iframes.length && out.urls.length < 16; i++) {
		out.urls.push(iframes[i].src || '');
	}
	return JSON.stringify(out);
})()
`

// ExtractTurnstileSitekey extracts the Turnstile sitekey from a page.
// It tries multiple methods to find the sitekey attribute.
func ExtractTurnstileSitekey(ctx context.Context, page *rod.Page) (string, error) {
	widget, err := ExtractTurnstileWidget(ctx, page)
	if err != nil {
		return "", err
	}
	return widget.SiteKey, nil
}

// ExtractTurnstileWidget finds the page's Turnstile widget without the help of
// the render() interceptor. It tries, in order:
//
//  1. the main frame's DOM: a .cf-turnstile element, another element with a
//     Turnstile-shaped data-sitekey, or a literal turnstile.render() call;
//  2. the src of an iframe served by challenges.cloudflare.com;
//  3. the same, through shadow roots and nested frames (managed challenges
//     render the Turnstile iframe inside a closed shadow root);
//  4. the DOM of out-of-process child frames tracked by the interceptor.
//
// Only the first method can know action and cData.
func ExtractTurnstileWidget(ctx context.Context, page *rod.Page) (*TurnstileWidget, error) {
	page = page.Context(ctx)

	if widget, err := extractWidgetJS(ctx, page); err == nil {
		log.Debug().Str("method", "js").Msg("Extracted sitekey via JavaScript")
		return widget, nil
	}

	methods := []struct {
		name string
		fn   func(context.Context, *rod.Page) (string, error)
	}{
		{"iframe", extractSitekeyIframe},
		{"pierce", extractSitekeyViaPierce},
		{"oopif_dom", extractSitekeyFromOOPIFChildren},
	}
	for _, method := range methods {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sitekey, err := method.fn(ctx, page)
		if err == nil && sitekey != "" {
			log.Debug().Str("method", method.name).Msg("Extracted sitekey")
			return &TurnstileWidget{SiteKey: sitekey}, nil
		}
	}

	return nil, types.ErrCaptchaSitekeyNotFound
}

// extractWidgetJS asks the main frame for candidate widgets and picks one.
func extractWidgetJS(ctx context.Context, page *rod.Page) (*TurnstileWidget, error) {
	raw, err := evalString(ctx, page, fmt.Sprintf(turnstileWidgetJS, maxWidgetCandidates))
	if err != nil {
		return nil, err
	}
	var candidates []widgetCandidate
	if err := json.Unmarshal([]byte(raw), &candidates); err != nil {
		return nil, fmt.Errorf("failed to parse widget candidates: %w", err)
	}
	widget, ok := pickTurnstileWidget(candidates)
	if !ok {
		return nil, errors.New("no turnstile widget found via js")
	}
	return widget, nil
}

// pickTurnstileWidget chooses the Turnstile widget among the page's candidates.
// A .cf-turnstile element wins over a bare data-sitekey attribute, which wins
// over a sitekey scraped from a script. Elements of another vendor's widget and
// keys that are not shaped like a Turnstile sitekey are never chosen.
func pickTurnstileWidget(candidates []widgetCandidate) (*TurnstileWidget, bool) {
	for _, source := range []string{"widget", "attribute", "script"} {
		for i := range candidates {
			c := &candidates[i]
			if c.Source != source || c.Foreign || !isTurnstileSitekey(c.SiteKey) {
				continue
			}
			widget := c.TurnstileWidget
			return &widget, true
		}
	}
	return nil, false
}

// isTurnstileSitekey reports whether key could be a Turnstile sitekey. It
// rejects the shapes that belong to other vendors: an hCaptcha sitekey is a
// UUID and a reCAPTCHA sitekey is 40 characters starting "6L". Cloudflare's own
// keys do not all start with "0x" (its test keys start "1x", "2x", "3x"), so
// no prefix is required.
func isTurnstileSitekey(key string) bool {
	if len(key) < minSitekeyLen || len(key) > maxSitekeyLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		if !isSitekeyChar(key[i]) && key[i] != '_' && key[i] != '-' {
			return false
		}
	}
	return !isUUID(key) && !isRecaptchaSitekey(key)
}

// isUUID reports whether s has the 8-4-4-4-12 hexadecimal shape.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// isRecaptchaSitekey reports whether s is shaped like a reCAPTCHA sitekey.
func isRecaptchaSitekey(s string) bool {
	return len(s) == recaptchaSitekeyLen && strings.HasPrefix(s, "6L")
}

// isTurnstileChallengeURL reports whether raw is a URL served by Cloudflare's
// challenge host. Matching on the host — not on the word "turnstile" appearing
// somewhere in the URL — keeps a page's own /turnstile-demo?sitekey=... links
// from being mistaken for the widget.
func isTurnstileChallengeURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	return strings.EqualFold(u.Hostname(), turnstileChallengeHost)
}

// sitekeyFromChallengeURL returns the sitekey carried by a Turnstile challenge
// iframe URL, or "" if raw is not such a URL or carries none.
func sitekeyFromChallengeURL(raw string) string {
	if !isTurnstileChallengeURL(raw) {
		return ""
	}
	key := extractSitekeyFromURL(raw)
	if !isTurnstileSitekey(key) {
		return ""
	}
	return key
}

// oopifCandidates is what oopifSitekeyJS reports from a child frame.
type oopifCandidates struct {
	Keys []string `json:"keys"`
	URLs []string `json:"urls"`
}

// pickOOPIFSitekey chooses a sitekey from what a child frame reported.
func pickOOPIFSitekey(c oopifCandidates) string {
	for _, key := range c.Keys {
		if isTurnstileSitekey(key) {
			return key
		}
	}
	for _, raw := range c.URLs {
		if key := sitekeyFromChallengeURL(raw); key != "" {
			return key
		}
	}
	return ""
}

// extractSitekeyFromOOPIFChildren searches for the sitekey in the DOM of any
// OOPIF (out-of-process iframe) child sessions tracked by the interceptor.
// This handles managed challenges (e.g. filecrypt.cc) where the Turnstile widget
// renders inside a cross-origin OOPIF invisible to the main frame's DOM methods.
// The interceptor's auto-attach tracks child sessions; we evaluate JS in each to
// find the sitekey directly in its DOM.
func extractSitekeyFromOOPIFChildren(ctx context.Context, page *rod.Page) (string, error) {
	st, ok := loadState(page)
	if !ok || st == nil || st.browser == nil {
		return "", errors.New("no OOPIF state available")
	}

	children := st.snapshot()
	if len(children) == 0 {
		return "", errors.New("no OOPIF children tracked")
	}

	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		result, err := rawCDP(ctx, st.browser, child, "Runtime.evaluate", map[string]any{
			"expression":    oopifSitekeyJS,
			"returnByValue": true,
		})
		if err != nil {
			log.Debug().Err(err).Msg("OOPIF DOM search: Runtime.evaluate failed")
			continue
		}

		var candidates oopifCandidates
		if err := json.Unmarshal([]byte(extractEvalString(result)), &candidates); err != nil {
			continue
		}
		if sitekey := pickOOPIFSitekey(candidates); sitekey != "" {
			log.Debug().Str("sitekey", sitekeyPreview(sitekey)).Msg("Found sitekey in OOPIF child DOM")
			return sitekey, nil
		}
	}

	return "", fmt.Errorf("no sitekey found in %d OOPIF children", len(children))
}

// extractEvalString extracts a string value from a CDP Runtime.evaluate response.
func extractEvalString(raw []byte) string {
	var out struct {
		Result struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"result"`
		ExceptionDetails *struct{} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return ""
	}
	if out.ExceptionDetails != nil {
		return ""
	}
	if out.Result.Type != "string" {
		return ""
	}
	return out.Result.Value
}

// extractSitekeyViaPierce walks the entire DOM tree (including closed shadow
// roots and nested iframe documents) looking for the Cloudflare Turnstile
// challenge iframe, and parses the sitekey out of its URL. This is the reliable
// path for managed challenges where the widget lives inside a shadow root.
func extractSitekeyViaPierce(ctx context.Context, page *rod.Page) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, extractionEvalTimeout)
	defer cancel()

	depth := -1
	result, err := proto.DOMGetDocument{
		Depth:  &depth,
		Pierce: true,
	}.Call(page.Context(ctx))
	if err != nil {
		return "", fmt.Errorf("failed to get pierced DOM tree: %w", err)
	}
	if result == nil || result.Root == nil {
		return "", errors.New("pierced DOM tree is empty")
	}

	found, visited := findChallengeSitekey(result.Root, maxPierceNodes)
	if found == "" {
		return "", fmt.Errorf("no turnstile sitekey found via pierce (nodes_visited=%d)", visited)
	}
	return found, nil
}

// findChallengeSitekey walks a pierced DOM tree for the sitekey in the src of a
// Turnstile challenge iframe, visiting at most maxNodes nodes.
func findChallengeSitekey(root *proto.DOMNode, maxNodes int) (found string, visited int) {
	var walk func(node *proto.DOMNode)
	walk = func(node *proto.DOMNode) {
		if node == nil || found != "" {
			return
		}
		visited++
		if visited > maxNodes {
			return
		}

		// Attributes is a flat [name, value, name, value, ...] slice. Only the
		// src of a frame can be the challenge iframe's URL.
		if strings.EqualFold(node.NodeName, "IFRAME") {
			for i := 0; i+1 < len(node.Attributes); i += 2 {
				if node.Attributes[i] != "src" {
					continue
				}
				if key := sitekeyFromChallengeURL(node.Attributes[i+1]); key != "" {
					found = key
					return
				}
			}
		}

		for _, shadow := range node.ShadowRoots {
			walk(shadow)
		}
		walk(node.ContentDocument)
		walk(node.TemplateContent)
		for _, child := range node.Children {
			walk(child)
		}
	}

	walk(root)
	return found, visited
}

// extractSitekeyIframe extracts sitekey from Turnstile iframe src URL.
func extractSitekeyIframe(ctx context.Context, page *rod.Page) (string, error) {
	raw, err := evalString(ctx, page, `
	(function() {
		var urls = [];
		var iframes = document.querySelectorAll('iframe[src]');
		for (var i = 0; i < iframes.length && urls.length < 64; i++) {
			urls.push(iframes[i].src || '');
		}
		return JSON.stringify(urls);
	})()`)
	if err != nil {
		return "", fmt.Errorf("failed to get iframes: %w", err)
	}

	var urls []string
	if err := json.Unmarshal([]byte(raw), &urls); err != nil {
		return "", fmt.Errorf("failed to parse iframe list: %w", err)
	}

	// Turnstile iframes have sitekey in the URL
	// Format: https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/if/ov2/av0/sitekey/...
	for _, src := range urls {
		if sitekey := sitekeyFromChallengeURL(src); sitekey != "" {
			return sitekey, nil
		}
	}

	return "", errors.New("no sitekey found in iframes")
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

// findSubstring finds the index of substr in s, or -1 if not found.
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// extractSitekeyFromURL tries to extract sitekey from a Turnstile iframe URL.
// It does not judge where the URL points: callers must first establish that it
// is a challenge URL (see sitekeyFromChallengeURL).
func extractSitekeyFromURL(rawURL string) string {
	// Common patterns in Turnstile iframe URLs:
	// - /sitekey/0x... in path
	// - sitekey=0x... in query string

	// Pattern 1: /sitekey/ followed by the key
	sitekeyPrefix := "/sitekey/"
	idx := findSubstring(rawURL, sitekeyPrefix)
	if idx >= 0 {
		start := idx + len(sitekeyPrefix)
		end := start
		for end < len(rawURL) && rawURL[end] != '/' && rawURL[end] != '?' && rawURL[end] != '&' {
			end++
		}
		if end > start {
			return rawURL[start:end]
		}
	}

	// Pattern 2: sitekey= in query string
	queryPrefix := "sitekey="
	idx = findSubstring(rawURL, queryPrefix)
	if idx >= 0 {
		start := idx + len(queryPrefix)
		end := start
		for end < len(rawURL) && rawURL[end] != '&' && rawURL[end] != '#' {
			end++
		}
		if end > start {
			return rawURL[start:end]
		}
	}

	// Pattern 3: Cloudflare *managed challenge* iframes embed the sitekey as a bare
	// path segment rather than after /sitekey/ or sitekey=, e.g.
	//   .../turnstile/f/ov2/av0/rch/<token>/0x4AAAAAAADnPIDROrmt1Wwj/light/...
	// Turnstile sitekeys are always "0x" followed by base62 characters, so match
	// the longest such run. Only trusted because the caller already verified the
	// URL belongs to challenges.cloudflare.com.
	if key := findTurnstileSitekeyToken(rawURL); key != "" {
		return key
	}

	return ""
}

// findTurnstileSitekeyToken scans s for a Cloudflare Turnstile sitekey token of
// the form "0x" + base62, length-bounded to avoid matching unrelated hex blobs.
func findTurnstileSitekeyToken(s string) string {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '0' || (s[i+1] != 'x' && s[i+1] != 'X') {
			continue
		}
		end := i + 2
		for end < len(s) && isSitekeyChar(s[end]) {
			end++
		}
		// Real sitekeys are ~24 chars ("0x" + 22). Require a sane minimum to
		// reject things like "0x0" or short hex fragments.
		if end-i >= 18 {
			return s[i:end]
		}
	}
	return ""
}

// isSitekeyChar reports whether c is valid inside a Turnstile sitekey body.
func isSitekeyChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ExtractHCaptchaSitekey extracts the hCaptcha sitekey from a page.
// It looks for the data-sitekey attribute on hCaptcha elements and iframes.
func ExtractHCaptchaSitekey(ctx context.Context, page *rod.Page) (string, error) {
	js := `
	(function() {
		// hCaptcha elements with data-sitekey
		var selectors = [
			'.h-captcha[data-sitekey]',
			'[data-hcaptcha-widget-id][data-sitekey]',
			'div.h-captcha[data-sitekey]'
		];

		for (var i = 0; i < selectors.length; i++) {
			var el = document.querySelector(selectors[i]);
			if (el) {
				var sitekey = el.getAttribute('data-sitekey');
				if (sitekey && sitekey.length > 10) {
					return sitekey;
				}
			}
		}

		// Check for hCaptcha in script initialization
		var scripts = document.querySelectorAll('script');
		for (var i = 0; i < scripts.length; i++) {
			var text = scripts[i].textContent || '';
			var match = text.match(/hcaptcha\.render\([^,]*,\s*\{[^}]*sitekey['":\s]+['"]([0-9a-f-]+)['"]/);
			if (match && match[1]) {
				return match[1];
			}
		}

		// Check for hCaptcha in iframe src
		var iframes = document.querySelectorAll('iframe');
		for (var i = 0; i < iframes.length; i++) {
			var src = iframes[i].src || '';
			if (src.indexOf('hcaptcha.com') !== -1) {
				var match = src.match(/sitekey=([0-9a-f-]+)/);
				if (match && match[1]) {
					return match[1];
				}
			}
		}

		return '';
	})()
	`

	sitekey, err := evalString(ctx, page, js)
	if err != nil {
		return "", fmt.Errorf("hCaptcha js evaluation failed: %w", err)
	}
	if sitekey == "" {
		return "", types.ErrCaptchaSitekeyNotFound
	}
	return sitekey, nil
}

// evalString evaluates a JavaScript expression in the page's main frame and
// returns its string result, bounded by ctx and a timeout of its own.
func evalString(ctx context.Context, page *rod.Page, js string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, extractionEvalTimeout)
	defer cancel()

	result, err := proto.RuntimeEvaluate{
		Expression:    js,
		ReturnByValue: true,
	}.Call(page.Context(ctx))
	if err != nil {
		return "", fmt.Errorf("js evaluation failed: %w", err)
	}
	if result == nil || result.Result == nil {
		return "", errors.New("empty result from js evaluation")
	}
	if result.ExceptionDetails != nil {
		return "", fmt.Errorf("js exception: %s", result.ExceptionDetails.Text)
	}
	return result.Result.Value.Str(), nil
}

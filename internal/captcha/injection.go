// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	// injectionEvalTimeout bounds one injection script.
	injectionEvalTimeout = 5 * time.Second

	// injectionPollInterval is how often the page is checked for the effect of
	// an injected token.
	injectionPollInterval = 500 * time.Millisecond
)

// injectionMethod is one way of handing a solved token to a page. Its script
// must evaluate to true only when it actually delivered the token: it wrote it
// into a response field the widget owns, or it called a callback and the
// callback returned normally. Dispatching an event or setting an attribute
// nobody is known to read does not count.
type injectionMethod struct {
	name   string
	script string // a JS function expression taking the token
}

// turnstileInjectionMethods are tried in order; every one that applies runs,
// because a real Turnstile both fills its field and calls its callback.
var turnstileInjectionMethods = []injectionMethod{
	{name: "response_field", script: turnstileFieldJS},
	{name: "callback", script: turnstileCallbackJS},
}

var hcaptchaInjectionMethods = []injectionMethod{
	{name: "hcaptcha_response_field", script: hcaptchaFieldJS},
	{name: "hcaptcha_callback", script: hcaptchaCallbackJS},
}

// turnstileFieldJS writes the token into Turnstile's own response fields.
// Turnstile names its field cf-turnstile-response; inside a .cf-turnstile
// container it may also add a g-recaptcha-response field for reCAPTCHA
// compatibility. A g-recaptcha-response or h-captcha-response field elsewhere
// belongs to a different captcha and is left alone.
const turnstileFieldJS = `function(token) {
	var fields = document.querySelectorAll(
		'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"], ' +
		'.cf-turnstile input[name="g-recaptcha-response"], .cf-turnstile textarea[name="g-recaptcha-response"]');
	var set = false;
	for (var i = 0; i < fields.length; i++) {
		fields[i].value = token;
		fields[i].dispatchEvent(new Event('input', { bubbles: true }));
		fields[i].dispatchEvent(new Event('change', { bubbles: true }));
		if (fields[i].name === 'cf-turnstile-response') set = true;
	}
	return set;
}`

// turnstileCallbackJS calls the data-callback of Turnstile widgets. Only if no
// widget names one does it fall back to a conventionally named global callback
// (the last resort for widgets rendered by script that the render() interceptor
// did not see), so a callback is never invoked twice with the same token.
const turnstileCallbackJS = `function(token) {
	var widgets = document.querySelectorAll('.cf-turnstile[data-callback]');
	var fired = false;
	var seen = [];
	for (var i = 0; i < widgets.length; i++) {
		var name = widgets[i].getAttribute('data-callback');
		if (name && seen.indexOf(name) === -1 && typeof window[name] === 'function') {
			seen.push(name);
			try { window[name](token); fired = true; } catch (e) {}
		}
	}
	if (fired) return true;
	var names = ['turnstileCallback', 'onTurnstileSuccess', 'handleTurnstile', 'cfCallback'];
	for (var i = 0; i < names.length; i++) {
		if (typeof window[names[i]] === 'function') {
			try { window[names[i]](token); return true; } catch (e) {}
		}
	}
	return false;
}`

// hcaptchaFieldJS writes the token into hCaptcha's response fields. hCaptcha
// adds an h-captcha-response field and, for compatibility, a
// g-recaptcha-response one next to it; only the former proves an hCaptcha
// widget is present.
const hcaptchaFieldJS = `function(token) {
	var own = document.querySelectorAll('textarea[name="h-captcha-response"], input[name="h-captcha-response"]');
	if (own.length === 0) return false;
	var compat = document.querySelectorAll(
		'.h-captcha textarea[name="g-recaptcha-response"], textarea[id^="g-recaptcha-response-"]');
	var fields = Array.prototype.slice.call(own).concat(Array.prototype.slice.call(compat));
	for (var i = 0; i < fields.length; i++) {
		fields[i].value = token;
		fields[i].dispatchEvent(new Event('input', { bubbles: true }));
		fields[i].dispatchEvent(new Event('change', { bubbles: true }));
	}
	return true;
}`

// hcaptchaCallbackJS calls the data-callback of hCaptcha widgets, or failing
// that a conventionally named global callback.
const hcaptchaCallbackJS = `function(token) {
	var fired = false;
	var widgets = document.querySelectorAll('.h-captcha[data-callback]');
	for (var i = 0; i < widgets.length; i++) {
		var name = widgets[i].getAttribute('data-callback');
		if (name && typeof window[name] === 'function') {
			try { window[name](token); fired = true; } catch (e) {}
		}
	}
	if (fired) return true;
	var names = ['hcaptchaCallback', 'onHCaptchaSuccess'];
	for (var i = 0; i < names.length; i++) {
		if (typeof window[names[i]] === 'function') {
			try { window[names[i]](token); return true; } catch (e) {}
		}
	}
	return false;
}`

// InjectTurnstileToken delivers a solved Turnstile token to the page. It
// returns nil only if the token really was delivered: written into a Turnstile
// response field, or passed to a callback that ran. A page with no such field
// and no callback yields types.ErrCaptchaTokenInjection.
func InjectTurnstileToken(ctx context.Context, page *rod.Page, token string) error {
	return injectToken(ctx, page, token, "Turnstile", turnstileInjectionMethods)
}

// InjectHCaptchaToken delivers a solved hCaptcha token to the page, with the
// same meaning of success as InjectTurnstileToken.
func InjectHCaptchaToken(ctx context.Context, page *rod.Page, token string) error {
	return injectToken(ctx, page, token, "hCaptcha", hcaptchaInjectionMethods)
}

// injectToken runs every method and reports success if at least one delivered
// the token.
func injectToken(ctx context.Context, page *rod.Page, token, kind string, methods []injectionMethod) error {
	if token == "" {
		return errors.New("empty token provided")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Safely encode the token for JavaScript; it is provider-controlled text.
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	delivered := false
	var lastErr error
	for _, method := range methods {
		if err := ctx.Err(); err != nil {
			return err
		}

		ok, err := evalWithContext(ctx, page, "("+method.script+")("+string(tokenJSON)+")")
		switch {
		case err != nil:
			lastErr = err
			log.Debug().Err(err).Str("captcha", kind).Str("method", method.name).Msg("Token injection method failed")
		case ok:
			delivered = true
			log.Info().Str("captcha", kind).Str("method", method.name).Msg("Token injection delivered the token")
		default:
			log.Debug().Str("captcha", kind).Str("method", method.name).Msg("Token injection method found nothing to deliver to")
		}
	}

	if delivered {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %w", types.ErrCaptchaTokenInjection, lastErr)
	}
	return fmt.Errorf("%w: no %s response field or callback on the page", types.ErrCaptchaTokenInjection, kind)
}

// evalWithContext evaluates a JavaScript expression in the page's main frame
// and returns its boolean result. The call is bound to ctx and to a short
// timeout of its own.
func evalWithContext(ctx context.Context, page *rod.Page, js string) (bool, error) {
	evalCtx, cancel := context.WithTimeout(ctx, injectionEvalTimeout)
	defer cancel()

	result, err := proto.RuntimeEvaluate{
		Expression:    js,
		ReturnByValue: true,
	}.Call(page.Context(evalCtx))
	if err != nil {
		return false, err
	}
	if result.ExceptionDetails != nil {
		return false, fmt.Errorf("js exception: %s", result.ExceptionDetails.Text)
	}
	if result.Result == nil {
		return false, errors.New("nil result")
	}
	return result.Result.Value.Bool(), nil
}

// WaitForTokenInjectionEffect waits for the page to process the injected token.
// Some sites need time to validate the token before proceeding.
func WaitForTokenInjectionEffect(ctx context.Context, page *rod.Page, timeout time.Duration) error {
	// Wait for potential redirects or form submissions
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Check for common success indicators
	js := `
	(function() {
		// Check if challenge is still visible
		var challenge = document.querySelector('#challenge-running, .cf-challenge-running, #turnstile-wrapper');
		if (challenge) {
			var style = window.getComputedStyle(challenge);
			if (style.display === 'none' || style.visibility === 'hidden') {
				return true; // Challenge hidden, likely succeeded
			}
		}

		// Check for success message
		var success = document.querySelector('.cf-challenge-success, .turnstile-success');
		if (success) {
			return true;
		}

		return false;
	})()
	`

	ticker := time.NewTicker(injectionPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			// Timeout is not necessarily an error - the injection might have worked
			// but we just can't detect the success indicator
			return nil
		case <-ticker.C:
			if ok, err := evalWithContext(waitCtx, page, js); err == nil && ok {
				log.Debug().Msg("Detected token injection success indicator")
				return nil
			}
		}
	}
}

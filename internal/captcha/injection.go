// Package captcha provides external CAPTCHA solver integration.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// InjectTurnstileToken injects a solved Turnstile token into the page.
// This triggers the Turnstile callback to process the token.
func InjectTurnstileToken(ctx context.Context, page *rod.Page, token string) error {
	if token == "" {
		return fmt.Errorf("empty token provided")
	}

	// Safety check for context
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Safely encode the token for JavaScript
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	log.Debug().
		Str("token_prefix", token[:min(20, len(token))]+"...").
		Msg("Injecting Turnstile token")

	// Try multiple injection methods
	methods := []struct {
		name string
		fn   func(context.Context, *rod.Page, string) error
	}{
		{"input_element", injectViaInputElement},
		{"callback", injectViaCallback},
		{"turnstile_api", injectViaTurnstileAPI},
		{"window_callback", injectViaWindowCallback},
	}

	var lastErr error
	for _, method := range methods {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := method.fn(ctx, page, string(tokenJSON))
		if err == nil {
			log.Info().Str("method", method.name).Msg("Token injection succeeded")
			return nil
		}
		lastErr = err
		log.Debug().
			Err(err).
			Str("method", method.name).
			Msg("Token injection method failed, trying next")
	}

	if lastErr != nil {
		return fmt.Errorf("all injection methods failed, last error: %w", lastErr)
	}

	return types.ErrCaptchaTokenInjection
}

// injectViaInputElement sets the token on the hidden input element.
func injectViaInputElement(ctx context.Context, page *rod.Page, tokenJSON string) error {
	js := fmt.Sprintf(`
	(function(token) {
		// Find the turnstile response input
		var selectors = [
			'input[name="cf-turnstile-response"]',
			'textarea[name="cf-turnstile-response"]',
			'input[name="g-recaptcha-response"]',
			'textarea[name="g-recaptcha-response"]',
			'input[name="h-captcha-response"]'
		];

		for (var i = 0; i < selectors.length; i++) {
			var input = document.querySelector(selectors[i]);
			if (input) {
				input.value = token;
				// Dispatch input event to trigger any listeners
				input.dispatchEvent(new Event('input', { bubbles: true }));
				input.dispatchEvent(new Event('change', { bubbles: true }));
				return true;
			}
		}

		return false;
	})(%s)
	`, tokenJSON)

	result, err := evalWithContext(ctx, page, js)
	if err != nil {
		return err
	}

	if !result {
		return fmt.Errorf("no input element found")
	}

	return nil
}

// injectViaCallback invokes the data-callback function on Turnstile widgets.
func injectViaCallback(ctx context.Context, page *rod.Page, tokenJSON string) error {
	js := fmt.Sprintf(`
	(function(token) {
		// Find elements with data-callback attribute
		var widgets = document.querySelectorAll('[data-callback]');
		for (var i = 0; i < widgets.length; i++) {
			var callbackName = widgets[i].getAttribute('data-callback');
			if (callbackName && typeof window[callbackName] === 'function') {
				try {
					window[callbackName](token);
					return true;
				} catch(e) {
					console.error('Callback error:', e);
				}
			}
		}

		// Also try cf-turnstile specific callback
		var cfWidgets = document.querySelectorAll('.cf-turnstile[data-callback]');
		for (var i = 0; i < cfWidgets.length; i++) {
			var callbackName = cfWidgets[i].getAttribute('data-callback');
			if (callbackName && typeof window[callbackName] === 'function') {
				try {
					window[callbackName](token);
					return true;
				} catch(e) {
					console.error('CF Callback error:', e);
				}
			}
		}

		return false;
	})(%s)
	`, tokenJSON)

	result, err := evalWithContext(ctx, page, js)
	if err != nil {
		return err
	}

	if !result {
		return fmt.Errorf("no callback function found")
	}

	return nil
}

// injectViaTurnstileAPI uses the official turnstile API if available.
func injectViaTurnstileAPI(ctx context.Context, page *rod.Page, tokenJSON string) error {
	js := fmt.Sprintf(`
	(function(token) {
		// Check if turnstile object exists
		if (typeof window.turnstile !== 'undefined') {
			// Try to find widget IDs and invoke callback
			var widgets = document.querySelectorAll('.cf-turnstile');
			for (var i = 0; i < widgets.length; i++) {
				var widgetId = widgets[i].getAttribute('data-turnstile-widget-id');
				if (widgetId) {
					// Store the token where turnstile expects it
					widgets[i].setAttribute('data-turnstile-response', token);

					// Also try to set on internal state
					if (window.turnstile && window.turnstile.widgets && window.turnstile.widgets[widgetId]) {
						window.turnstile.widgets[widgetId].response = token;
					}
				}
			}

			// Dispatch custom event that some implementations listen for
			var event = new CustomEvent('turnstile-success', { detail: { token: token } });
			document.dispatchEvent(event);
			window.dispatchEvent(event);

			return true;
		}
		return false;
	})(%s)
	`, tokenJSON)

	result, err := evalWithContext(ctx, page, js)
	if err != nil {
		return err
	}

	if !result {
		return fmt.Errorf("turnstile API not available")
	}

	return nil
}

// injectViaWindowCallback looks for common callback patterns on window.
func injectViaWindowCallback(ctx context.Context, page *rod.Page, tokenJSON string) error {
	js := fmt.Sprintf(`
	(function(token) {
		// Common callback function names
		var callbackNames = [
			'turnstileCallback',
			'onTurnstileSuccess',
			'handleTurnstile',
			'cfCallback',
			'captchaCallback',
			'onCaptchaSuccess',
			'grecaptchaCallback',
			'hcaptchaCallback'
		];

		for (var i = 0; i < callbackNames.length; i++) {
			var name = callbackNames[i];
			if (typeof window[name] === 'function') {
				try {
					window[name](token);
					return true;
				} catch(e) {
					console.error('Callback ' + name + ' error:', e);
				}
			}
		}

		// Also check for callbacks attached to form elements
		var forms = document.querySelectorAll('form');
		for (var i = 0; i < forms.length; i++) {
			var form = forms[i];
			var onsubmit = form.getAttribute('onsubmit');
			if (onsubmit && onsubmit.indexOf('turnstile') !== -1) {
				// Set the token and trigger submit
				var input = form.querySelector('input[name="cf-turnstile-response"]');
				if (input) {
					input.value = token;
					return true;
				}
			}
		}

		return false;
	})(%s)
	`, tokenJSON)

	result, err := evalWithContext(ctx, page, js)
	if err != nil {
		return err
	}

	if !result {
		return fmt.Errorf("no window callback found")
	}

	return nil
}

// evalWithContext evaluates JavaScript with context timeout support.
func evalWithContext(ctx context.Context, page *rod.Page, js string) (bool, error) {
	// Create timeout for evaluation
	evalCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resultChan := make(chan struct {
		result bool
		err    error
	}, 1)

	go func() {
		result, err := proto.RuntimeEvaluate{
			Expression:    js,
			ReturnByValue: true,
		}.Call(page)

		if err != nil {
			resultChan <- struct {
				result bool
				err    error
			}{false, err}
			return
		}

		if result.ExceptionDetails != nil {
			resultChan <- struct {
				result bool
				err    error
			}{false, fmt.Errorf("js exception: %s", result.ExceptionDetails.Text)}
			return
		}

		if result.Result == nil {
			resultChan <- struct {
				result bool
				err    error
			}{false, fmt.Errorf("nil result")}
			return
		}

		// Check if the result is a boolean true
		success := result.Result.Value.Bool()
		resultChan <- struct {
			result bool
			err    error
		}{success, nil}
	}()

	select {
	case <-evalCtx.Done():
		return false, evalCtx.Err()
	case r := <-resultChan:
		return r.result, r.err
	}
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

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			// Timeout is not necessarily an error - the injection might have worked
			// but we just can't detect the success indicator
			return nil
		case <-ticker.C:
			result, err := proto.RuntimeEvaluate{
				Expression:    js,
				ReturnByValue: true,
			}.Call(page)

			if err == nil && result != nil && result.Result != nil {
				if result.Result.Value.Bool() {
					log.Debug().Msg("Detected token injection success indicator")
					return nil
				}
			}
		}
	}
}

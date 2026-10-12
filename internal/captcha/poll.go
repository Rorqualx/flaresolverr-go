package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

const (
	// maxProviderResponseBytes bounds how much of a provider response is read.
	// Real responses are a few hundred bytes; anything near this is not one.
	maxProviderResponseBytes = 1 << 20

	// maxTransientPollErrors is how many consecutive transient failures a poll
	// tolerates before giving up on a task that has already been paid for.
	maxTransientPollErrors = 3

	// maxPollBackoffFactor caps how far the poll interval stretches while a
	// provider keeps failing transiently.
	maxPollBackoffFactor = 3

	// maxProviderMessageLen bounds provider-supplied text copied into an error.
	maxProviderMessageLen = 200
)

// transientError marks a failure that is worth retrying: a network error, an
// HTTP 429/5xx, or a body that is not the provider's JSON (a gateway's HTML
// error page). The task, if one exists, is probably still being worked on.
type transientError struct{ err error }

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func asTransient(err error) error { return &transientError{err: err} }

func isTransient(err error) bool {
	var t *transientError
	return errors.As(err, &t)
}

// preTaskError marks a failure that happened before the provider accepted a
// task, so nothing was bought: an unsupported request, a rejected key, an empty
// balance. The chain may try another provider without spending its budget.
type preTaskError struct{ err error }

func (e *preTaskError) Error() string { return e.err.Error() }
func (e *preTaskError) Unwrap() error { return e.err }

// notCreated wraps err to record that no task was created at the provider.
func notCreated(err error) error { return &preTaskError{err: err} }

// TaskCreated reports whether a failed solve got as far as creating a task at
// the provider. It is false only when the provider definitively refused the
// request; an ambiguous failure (the request may have been accepted) counts as
// created, because the provider may bill for it.
func TaskCreated(err error) bool {
	if err == nil {
		return true
	}
	var pre *preTaskError
	return !errors.As(err, &pre)
}

// createFailure classifies a failed task-creation request. A request that never
// left this machine (DNS or connect failure) certainly created nothing, so it is
// marked "not created"; anything later is ambiguous and is left as it is.
func createFailure(err error) error {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	if errors.As(err, &dnsErr) || (errors.As(err, &opErr) && opErr.Op == "dial") {
		return notCreated(err)
	}
	return err
}

// scrub removes a secret from provider-supplied text before it reaches a log or
// an error. Providers have been known to echo the key back in a description.
func scrub(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[redacted]")
}

// providerMessage prepares a provider-supplied description for an error.
func providerMessage(description, fallback, secret string) string {
	if description == "" {
		description = fallback
	}
	return scrub(truncate(description, maxProviderMessageLen), secret)
}

// doJSON sends one request to a provider and decodes its JSON response into out.
// body, if non-nil, is sent as a JSON POST body. The response is read through a
// size limit. Network errors, HTTP 429/5xx and non-JSON bodies are returned as
// transient errors; the request URL is never included in an error, because some
// providers carry the API key in it.
func doJSON(ctx context.Context, client *http.Client, method, reqURL string, body, out interface{}) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		// The underlying error embeds the URL; do not pass it on.
		return errors.New("failed to create request: invalid provider URL")
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		// SECURITY: *url.Error embeds the full request URL, which for some
		// providers carries the API key as a query parameter. Keep the cause only.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return asTransient(fmt.Errorf("request failed: %w", err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponseBytes+1))
	if err != nil {
		return asTransient(fmt.Errorf("failed to read response: %w", err))
	}
	if len(respBody) > maxProviderResponseBytes {
		return fmt.Errorf("provider response exceeds %d bytes", maxProviderResponseBytes)
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		return asTransient(fmt.Errorf("provider returned HTTP %d", resp.StatusCode))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return asTransient(fmt.Errorf("provider returned a non-JSON response (HTTP %d)", resp.StatusCode))
	}
	return nil
}

// pollConfig describes how to wait for one provider task.
type pollConfig struct {
	provider string
	taskID   string
	timeout  time.Duration
	interval time.Duration
}

// pollTask calls fetch until it reports the task ready, fails permanently, or
// the timeout expires. The first call happens one interval after the task was
// created. A transient failure does not abandon the task: the provider is still
// working on something that has been paid for, so the poll backs off and tries
// again, giving up only after maxTransientPollErrors failures in a row.
func pollTask[T any](ctx context.Context, cfg pollConfig, fetch func(context.Context) (result T, ready bool, err error)) (T, error) {
	var zero T

	pollCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	timer := time.NewTimer(cfg.interval)
	defer timer.Stop()

	consecutiveTransient := 0
	for {
		select {
		case <-pollCtx.Done():
			return zero, types.NewCaptchaTimeoutError(cfg.provider, cfg.taskID)
		case <-timer.C:
		}

		result, ready, err := fetch(pollCtx)
		switch {
		case err == nil && ready:
			return result, nil
		case err == nil:
			consecutiveTransient = 0
		case pollCtx.Err() != nil:
			return zero, types.NewCaptchaTimeoutError(cfg.provider, cfg.taskID)
		case isTransient(err):
			consecutiveTransient++
			if consecutiveTransient > maxTransientPollErrors {
				return zero, &types.CaptchaError{
					Provider: cfg.provider,
					TaskID:   cfg.taskID,
					Message: fmt.Sprintf("%s: gave up polling after %d consecutive errors: %v",
						cfg.provider, consecutiveTransient, err),
					Err: types.ErrCaptchaSolverRejected,
				}
			}
			log.Warn().
				Err(err).
				Str("provider", cfg.provider).
				Str("task_id", cfg.taskID).
				Int("consecutive", consecutiveTransient).
				Msg("Transient error polling captcha task, will retry")
		default:
			return zero, err
		}

		timer.Reset(cfg.interval * time.Duration(min(consecutiveTransient+1, maxPollBackoffFactor)))
	}
}

// flexString decodes a JSON string or number into a string. Provider APIs are
// inconsistent about which one they send for ids and amounts.
type flexString string

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*f = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("expected a string or number, got %s", truncate(string(data), 32))
	}
	*f = flexString(n.String())
	return nil
}

// float returns the value as a float64, or 0 if it is not numeric.
func (f flexString) float() float64 {
	v, err := strconv.ParseFloat(string(f), 64)
	if err != nil {
		return 0
	}
	return v
}

// truncate shortens s to at most n bytes for use in messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// solution is the solved-task payload shared by the createTask-style providers.
// Turnstile solutions carry "token"; hCaptcha solutions have used
// "gRecaptchaResponse" at some providers and "token" at others.
type solution struct {
	Token              string `json:"token"`
	GRecaptchaResponse string `json:"gRecaptchaResponse"`
	UserAgent          string `json:"userAgent"`
}

// value returns whichever token field the provider filled in.
func (s *solution) value() string {
	if s == nil {
		return ""
	}
	if s.Token != "" {
		return s.Token
	}
	return s.GRecaptchaResponse
}

// agent returns the User-Agent the provider's worker used, if reported.
func (s *solution) agent() string {
	if s == nil {
		return ""
	}
	return s.UserAgent
}

// sitekeyPreview shortens a sitekey for logs.
func sitekeyPreview(sitekey string) string {
	return truncate(sitekey, 10)
}

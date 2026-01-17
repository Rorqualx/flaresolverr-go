package browser

import (
	"context"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// ProxyConfig holds proxy settings for a request.
type ProxyConfig struct {
	URL      string
	Username string
	Password string
}

// SetPageProxy configures proxy authentication for a page.
// This handles proxy authentication challenges via CDP.
//
// Note: The proxy server itself must be set at browser launch time.
// This function only handles authentication for authenticated proxies.
//
// Returns a cleanup function that MUST be called when the page is closed
// to prevent goroutine leaks from EachEvent listeners. The cleanup function
// is safe to call multiple times.
func SetPageProxy(ctx context.Context, page *rod.Page, proxy *ProxyConfig) (cleanup func(), err error) {
	if proxy == nil || proxy.URL == "" {
		return func() {}, nil
	}

	// If proxy requires authentication, set up auth handler
	if proxy.Username != "" {
		log.Debug().
			Bool("has_credentials", true).
			Msg("Setting up proxy authentication")

		// Enable fetch domain to intercept auth challenges
		err := proto.FetchEnable{
			HandleAuthRequests: true,
		}.Call(page)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to enable fetch for proxy auth")
			return func() {}, err
		}

		// Create cancellable context for event listeners
		// This context is canceled when cleanup is called OR when parent context is done
		listenerCtx, cancel := context.WithCancel(ctx)
		pageWithCtx := page.Context(listenerCtx)

		// Fix #2: Add WaitGroup to track EachEvent goroutines to prevent leaks
		var wg sync.WaitGroup

		// Track cleanup state to prevent double-cancel
		var cleanupOnce sync.Once
		cleanupFunc := func() {
			cleanupOnce.Do(func() {
				cancel()
				// Wait for goroutines to finish with timeout
				done := make(chan struct{})
				go func() {
					wg.Wait()
					close(done)
				}()
				select {
				case <-done:
					log.Debug().Msg("Proxy authentication listeners cleaned up")
				case <-time.After(5 * time.Second):
					log.Warn().Msg("Timeout waiting for proxy auth listeners to cleanup")
				}
			})
		}

		// Monitor for page close to auto-cleanup goroutines
		wg.Add(1)
		go func() {
			defer wg.Done()
			pageWithCtx.EachEvent(func(e *proto.TargetTargetDestroyed) bool {
				cleanupFunc()
				return true // Stop listening
			})()
		}()

		// Handle authentication challenges
		wg.Add(1)
		go func() {
			defer wg.Done()
			pageWithCtx.EachEvent(func(e *proto.FetchAuthRequired) bool {
				select {
				case <-listenerCtx.Done():
					return true // Stop listening
				default:
				}
				log.Debug().Msg("Proxy authentication required, providing credentials")

				// Ignore error: request may have been canceled or timed out
				_ = proto.FetchContinueWithAuth{
					RequestID: e.RequestID,
					AuthChallengeResponse: &proto.FetchAuthChallengeResponse{
						Response: proto.FetchAuthChallengeResponseResponseProvideCredentials,
						Username: proxy.Username,
						Password: proxy.Password,
					},
				}.Call(page)
				return false // Continue listening
			})()
		}()

		// Handle regular paused requests (continue them)
		wg.Add(1)
		go func() {
			defer wg.Done()
			pageWithCtx.EachEvent(func(e *proto.FetchRequestPaused) bool {
				select {
				case <-listenerCtx.Done():
					return true // Stop listening
				default:
				}
				// Only continue if not an auth challenge (no response status means it's a request)
				if e.ResponseStatusCode == nil {
					// Ignore error: request may have been canceled or timed out
					_ = proto.FetchContinueRequest{
						RequestID: e.RequestID,
					}.Call(page)
				}
				return false // Continue listening
			})()
		}()

		return cleanupFunc, nil
	}

	return func() {}, nil
}

// GetProxyArg returns the Chrome argument for proxy server.
// This should be used when launching the browser.
func GetProxyArg(proxyURL string) string {
	if proxyURL == "" {
		return ""
	}
	return proxyURL
}

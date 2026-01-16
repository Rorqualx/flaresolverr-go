package browser

import (
	"context"

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
// Bug 1: Returns a cleanup function that must be called when the page is closed
// to prevent goroutine leaks from EachEvent listeners.
func SetPageProxy(ctx context.Context, page *rod.Page, proxy *ProxyConfig) (cleanup func(), err error) {
	if proxy == nil || proxy.URL == "" {
		return func() {}, nil
	}

	// If proxy requires authentication, set up auth handler
	if proxy.Username != "" {
		log.Debug().
			Str("proxy_url", proxy.URL).
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

		// Bug 1: Create cancellable context for event listeners
		listenerCtx, cancel := context.WithCancel(ctx)
		pageWithCtx := page.Context(listenerCtx)

		// Handle authentication challenges
		go func() {
			pageWithCtx.EachEvent(func(e *proto.FetchAuthRequired) bool {
				select {
				case <-listenerCtx.Done():
					return true // Stop listening
				default:
				}
				log.Debug().Msg("Proxy authentication required, providing credentials")

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

		// Also handle regular paused requests (continue them)
		go func() {
			pageWithCtx.EachEvent(func(e *proto.FetchRequestPaused) bool {
				select {
				case <-listenerCtx.Done():
					return true // Stop listening
				default:
				}
				// Only continue if not an auth challenge (no response status means it's a request)
				if e.ResponseStatusCode == nil {
					_ = proto.FetchContinueRequest{
						RequestID: e.RequestID,
					}.Call(page)
				}
				return false // Continue listening
			})()
		}()

		return cancel, nil
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

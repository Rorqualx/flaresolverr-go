package browser

import (
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// browserContextTimeout bounds creating and disposing a browser context.
const browserContextTimeout = 10 * time.Second

// NewIsolatedContext creates a fresh browser context on b and returns a handle
// whose pages live inside it, plus a function that disposes the context.
//
// A browser context has its own cookies, localStorage, cache and service
// workers, so nothing one caller leaves behind is visible to the next caller
// that uses the same browser process. proxyServer, if non-empty, routes the
// context's traffic through that proxy instead of the browser's default.
//
// The returned handle shares b's connection and context: pages created from it
// keep working until dispose is called. dispose closes any page still open in
// the context and is safe to call more than once.
func NewIsolatedContext(b *rod.Browser, proxyServer string) (isolated *rod.Browser, dispose func(), err error) {
	return newIsolatedContext(b, proxyServer, "")
}

// newIsolatedContext is NewIsolatedContext with a proxy bypass list for the
// context's proxy.
func newIsolatedContext(b *rod.Browser, proxyServer, proxyBypassList string) (isolated *rod.Browser, dispose func(), err error) {
	res, err := proto.TargetCreateBrowserContext{
		ProxyServer:     proxyServer,
		ProxyBypassList: proxyBypassList,
		DisposeOnDetach: true, // a dropped CDP connection must not leave the context behind
	}.Call(b.Timeout(browserContextTimeout))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create browser context: %w", err)
	}

	isolated = b.Context(b.GetContext()) // a copy that shares the connection
	isolated.BrowserContextID = res.BrowserContextID

	dispose = func() {
		disposeBrowserContext(b, res.BrowserContextID)
	}
	return isolated, dispose, nil
}

// disposeBrowserContext removes a browser context and everything stored in it.
func disposeBrowserContext(b *rod.Browser, id proto.BrowserBrowserContextID) {
	err := proto.TargetDisposeBrowserContext{BrowserContextID: id}.Call(b.Timeout(browserContextTimeout))
	if err != nil {
		// Also reached on a second dispose or a dead browser; neither is actionable.
		log.Debug().Err(err).Msg("Failed to dispose browser context")
	}
}

// disposeAllContexts removes every non-default browser context on b. The pool
// calls it when a browser is released, as a backstop for a context whose owner
// failed to dispose it.
func disposeAllContexts(b *rod.Browser) {
	res, err := proto.TargetGetBrowserContexts{}.Call(b.Timeout(browserContextTimeout))
	if err != nil {
		log.Debug().Err(err).Msg("Failed to list browser contexts")
		return
	}
	for _, id := range res.BrowserContextIDs {
		disposeBrowserContext(b, id)
	}
}

package browser

import (
	"context"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// ApplyStealthToPage applies anti-detection measures to a page.
// This should be called after page creation but BEFORE navigation.
//
// The stealth patches modify JavaScript properties that are commonly
// used to detect headless browsers and automation tools.
func ApplyStealthToPage(page *rod.Page) error {
	log.Debug().Msg("Applying stealth patches to page")

	// Inject stealth script before any page content loads
	// Use MustEval wrapped in recover to prevent crashes
	_, err := page.Evaluate(rod.Eval(stealthScript))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to apply stealth script")
		// Don't return error - stealth is best-effort
		return nil
	}

	return nil
}

// stealthScript contains JavaScript to mask automation.
// These patches address common detection vectors used by anti-bot systems.
const stealthScript = `
(() => {
    'use strict';

    // Wrap everything in try-catch to prevent any single failure from breaking the script
    try {

    // ========================================
    // 1. Remove webdriver property
    // ========================================
    // This is the most common detection vector.
    // Automation tools set navigator.webdriver = true
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true
    });

    // ========================================
    // 2. Mock plugins array
    // ========================================
    // Headless browsers typically have empty plugins.
    // Real browsers have PDF viewer and other plugins.
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const plugins = [
                {
                    name: 'Chrome PDF Plugin',
                    filename: 'internal-pdf-viewer',
                    description: 'Portable Document Format',
                    length: 1,
                    item: () => null,
                    namedItem: () => null,
                    [Symbol.iterator]: function* () {}
                },
                {
                    name: 'Chrome PDF Viewer',
                    filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
                    description: '',
                    length: 1,
                    item: () => null,
                    namedItem: () => null,
                    [Symbol.iterator]: function* () {}
                },
                {
                    name: 'Native Client',
                    filename: 'internal-nacl-plugin',
                    description: '',
                    length: 2,
                    item: () => null,
                    namedItem: () => null,
                    [Symbol.iterator]: function* () {}
                }
            ];
            plugins.length = 3;
            plugins.item = (index) => plugins[index] || null;
            plugins.namedItem = (name) => plugins.find(p => p.name === name) || null;
            plugins.refresh = () => {};
            return plugins;
        },
        configurable: true
    });

    // ========================================
    // 3. Mock languages
    // ========================================
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true
    });

    // ========================================
    // 4. Add chrome runtime object
    // ========================================
    // Real Chrome browsers have window.chrome with various properties.
    if (!window.chrome) {
        window.chrome = {};
    }
    if (!window.chrome.runtime) {
        window.chrome.runtime = {
            connect: function() { return { onMessage: { addListener: function() {} }, postMessage: function() {} }; },
            sendMessage: function() {},
            onMessage: { addListener: function() {} },
            id: undefined
        };
    }
    if (!window.chrome.csi) {
        window.chrome.csi = function() { return {}; };
    }
    if (!window.chrome.loadTimes) {
        window.chrome.loadTimes = function() {
            return {
                requestTime: Date.now() / 1000,
                startLoadTime: Date.now() / 1000,
                commitLoadTime: Date.now() / 1000,
                finishDocumentLoadTime: Date.now() / 1000,
                finishLoadTime: Date.now() / 1000,
                firstPaintTime: Date.now() / 1000,
                firstPaintAfterLoadTime: 0,
                navigationType: 'navigate',
                wasFetchedViaSpdy: false,
                wasNpnNegotiated: true,
                npnNegotiatedProtocol: 'h2',
                wasAlternateProtocolAvailable: false,
                connectionInfo: 'h2'
            };
        };
    }

    // ========================================
    // 5. Mock permissions API
    // ========================================
    if (window.navigator && window.navigator.permissions && window.navigator.permissions.query) {
        const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
        window.navigator.permissions.query = (parameters) => {
            if (parameters.name === 'notifications') {
                return Promise.resolve({
                    state: typeof Notification !== 'undefined' ? Notification.permission : 'default',
                    onchange: null
                });
            }
            return originalQuery(parameters);
        };
    }

    // ========================================
    // 6. Mock connection type
    // ========================================
    // Headless browsers may have unusual connection properties
    if (navigator.connection) {
        Object.defineProperty(navigator, 'connection', {
            get: () => ({
                effectiveType: '4g',
                rtt: 50,
                downlink: 10,
                saveData: false,
                onchange: null
            }),
            configurable: true
        });
    }

    // ========================================
    // 7. Hardware concurrency
    // ========================================
    // VMs and containers may report unusual values
    Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: () => 8,
        configurable: true
    });

    // ========================================
    // 8. Device memory
    // ========================================
    Object.defineProperty(navigator, 'deviceMemory', {
        get: () => 8,
        configurable: true
    });

    // ========================================
    // 9. Fix toString leaks
    // ========================================
    // Some detection scripts check if functions have been modified
    // by calling toString() on them
    const originalFunctionToString = Function.prototype.toString;

    const customFunctionToString = function() {
        try {
            if (window.navigator && window.navigator.permissions && this === window.navigator.permissions.query) {
                return 'function query() { [native code] }';
            }
            if (window.chrome && window.chrome.runtime) {
                if (this === window.chrome.runtime.connect) {
                    return 'function connect() { [native code] }';
                }
                if (this === window.chrome.runtime.sendMessage) {
                    return 'function sendMessage() { [native code] }';
                }
            }
        } catch (e) {
            // Ignore errors during comparison
        }
        return originalFunctionToString.call(this);
    };

    Object.defineProperty(Function.prototype, 'toString', {
        value: customFunctionToString,
        writable: true,
        configurable: true
    });

    // ========================================
    // 10. WebGL vendor/renderer
    // ========================================
    // Spoof WebGL to avoid detection of VM/headless
    try {
        if (typeof Proxy !== 'undefined' && typeof Reflect !== 'undefined') {
            const getParameterProxyHandler = {
                apply: function(target, thisArg, args) {
                    const param = args[0];

                    // UNMASKED_VENDOR_WEBGL
                    if (param === 37445) {
                        return 'Intel Inc.';
                    }
                    // UNMASKED_RENDERER_WEBGL
                    if (param === 37446) {
                        return 'Intel Iris OpenGL Engine';
                    }

                    return Reflect.apply(target, thisArg, args);
                }
            };

            // Apply to both WebGL contexts
            ['WebGLRenderingContext', 'WebGL2RenderingContext'].forEach(ctx => {
                try {
                    if (window[ctx] && window[ctx].prototype && typeof window[ctx].prototype.getParameter === 'function') {
                        const getParameter = window[ctx].prototype.getParameter;
                        window[ctx].prototype.getParameter = new Proxy(getParameter, getParameterProxyHandler);
                    }
                } catch (e) {
                    // Skip this context if it fails
                }
            });
        }
    } catch (e) {
        // WebGL spoofing failed, continue anyway
    }

    // ========================================
    // 11. Notification permission
    // ========================================
    // Make Notification.permission return 'default' instead of 'denied'
    // which is common in headless browsers
    if (typeof Notification !== 'undefined') {
        Object.defineProperty(Notification, 'permission', {
            get: () => 'default',
            configurable: true
        });
    }

    console.debug('[Stealth] Anti-detection patches applied');

    } catch (e) {
        console.debug('[Stealth] Some patches failed:', e.message);
    }
})();
`

// BlockResources configures the page to block unnecessary resources.
// This reduces memory usage and speeds up page loading.
//
// Parameters:
//   - blockImages: Block image resources (png, jpg, gif, etc.)
//   - blockCSS: Block stylesheet resources
//   - blockFonts: Block font resources (woff, ttf, etc.)
//   - blockMedia: Block video and audio resources
//
// Bug 1: Returns a cleanup function that must be called when the page is closed
// to prevent goroutine leaks from EachEvent listeners.
func BlockResources(ctx context.Context, page *rod.Page, blockImages, blockCSS, blockFonts, blockMedia bool) (cleanup func(), err error) {
	log.Debug().
		Bool("images", blockImages).
		Bool("css", blockCSS).
		Bool("fonts", blockFonts).
		Bool("media", blockMedia).
		Msg("Configuring resource blocking")

	// Enable fetch domain for request interception
	err = proto.FetchEnable{
		Patterns: buildBlockPatterns(blockImages, blockCSS, blockFonts, blockMedia),
	}.Call(page)

	if err != nil {
		log.Warn().Err(err).Msg("Failed to enable resource blocking")
		return func() {}, err
	}

	// Bug 1: Create cancellable context for event listeners
	listenerCtx, cancel := context.WithCancel(ctx)
	pageWithCtx := page.Context(listenerCtx)

	// Handle intercepted requests using Rod's EachEvent
	go func() {
		pageWithCtx.EachEvent(func(e *proto.FetchRequestPaused) bool {
			select {
			case <-listenerCtx.Done():
				return true // Stop listening
			default:
			}
			// Fail blocked requests
			_ = proto.FetchFailRequest{
				RequestID:   e.RequestID,
				ErrorReason: proto.NetworkErrorReasonBlockedByClient,
			}.Call(page)
			return false // Continue listening
		})()
	}()

	return cancel, nil
}

// buildBlockPatterns creates the list of URL patterns to block.
func buildBlockPatterns(blockImages, blockCSS, blockFonts, blockMedia bool) []*proto.FetchRequestPattern {
	patterns := make([]*proto.FetchRequestPattern, 0)

	if blockImages {
		imagePatterns := []string{
			"*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.svg", "*.ico", "*.bmp",
		}
		for _, p := range imagePatterns {
			patterns = append(patterns, &proto.FetchRequestPattern{
				URLPattern:   p,
				ResourceType: proto.NetworkResourceTypeImage,
			})
		}
	}

	if blockCSS {
		patterns = append(patterns, &proto.FetchRequestPattern{
			URLPattern:   "*.css",
			ResourceType: proto.NetworkResourceTypeStylesheet,
		})
	}

	if blockFonts {
		fontPatterns := []string{"*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot"}
		for _, p := range fontPatterns {
			patterns = append(patterns, &proto.FetchRequestPattern{
				URLPattern:   p,
				ResourceType: proto.NetworkResourceTypeFont,
			})
		}
	}

	if blockMedia {
		mediaPatterns := []string{"*.mp4", "*.webm", "*.mp3", "*.ogg", "*.wav"}
		for _, p := range mediaPatterns {
			patterns = append(patterns, &proto.FetchRequestPattern{
				URLPattern:   p,
				ResourceType: proto.NetworkResourceTypeMedia,
			})
		}
	}

	return patterns
}

// SetUserAgent sets a custom user agent on the page.
func SetUserAgent(page *rod.Page, userAgent string) error {
	return proto.NetworkSetUserAgentOverride{
		UserAgent: userAgent,
	}.Call(page)
}

// SetViewport sets the page viewport size.
func SetViewport(page *rod.Page, width, height int) error {
	return page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:             width,
		Height:            height,
		DeviceScaleFactor: 1,
		Mobile:            false,
	})
}

// SetCookies sets cookies on the page.
func SetCookies(page *rod.Page, cookies []*proto.NetworkCookieParam) error {
	return page.SetCookies(cookies)
}

// GetCookies retrieves all cookies from the page.
func GetCookies(page *rod.Page) ([]*proto.NetworkCookie, error) {
	return page.Cookies(nil)
}

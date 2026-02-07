package browser

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// ApplyStealthToPage applies anti-detection measures to a page.
// This should be called after page creation but BEFORE navigation.
//
// The stealth patches modify JavaScript properties that are commonly
// used to detect headless browsers and automation tools.
//
// Returns an error for critical failures (e.g., syntax errors in stealth script),
// but logs and continues for non-critical issues (e.g., APIs not available on about:blank).
func ApplyStealthToPage(page *rod.Page) error {
	log.Debug().Msg("Applying stealth patches to page")

	// Inject stealth script before any page content loads
	// Use MustEval wrapped in recover to prevent crashes
	_, err := page.Evaluate(rod.Eval(stealthScript))
	if err != nil {
		errStr := err.Error()

		// Critical errors that indicate broken stealth script - return error
		if strings.Contains(errStr, "SyntaxError") {
			return fmt.Errorf("stealth script syntax error: %w", err)
		}
		if strings.Contains(errStr, "ReferenceError") {
			return fmt.Errorf("stealth script reference error: %w", err)
		}

		// Non-critical errors - log and continue
		// Common on about:blank pages where some APIs don't exist yet
		log.Warn().Err(err).Msg("Stealth script had non-fatal errors, continuing")
		return nil
	}

	return nil
}

// stealthScript contains JavaScript to mask automation.
// These patches address common detection vectors used by anti-bot systems.
const stealthScript = `
(() => {
    'use strict';

    // Global flag to prevent re-applying stealth on session page reuse
    // This survives across navigations within the same page context
    if (window.__stealthApplied) {
        return;
    }
    window.__stealthApplied = true;

    // Check if we're on about:blank - skip non-essential patches
    // about:blank pages don't have full API support for canvas, audio, etc.
    let isAboutBlank = false;
    try {
        isAboutBlank = window.location && window.location.href === 'about:blank';
    } catch (e) {
        // location access failed, assume not about:blank
    }

    // Wrap everything in try-catch to prevent any single failure from breaking the script
    try {

    // ========================================
    // 0. Block WebRTC at JavaScript level
    // ========================================
    // CRITICAL: Prevents WebRTC IP leaks that can expose the server's real IP
    // even when using a proxy. This complements the Chrome --force-webrtc-ip-handling-policy
    // flag but provides defense-in-depth at the JavaScript API level.
    // Note: Some sites detect undefined WebRTC as a bot signal, so we use
    // dummy constructors that throw errors on instantiation.
    try {
        // Block RTCPeerConnection - primary WebRTC class
        window.RTCPeerConnection = function() {
            throw new DOMException('RTCPeerConnection is not supported', 'NotSupportedError');
        };
        window.webkitRTCPeerConnection = window.RTCPeerConnection;
        window.mozRTCPeerConnection = window.RTCPeerConnection;

        // Block RTCDataChannel
        window.RTCDataChannel = function() {
            throw new DOMException('RTCDataChannel is not supported', 'NotSupportedError');
        };

        // Block RTCSessionDescription
        window.RTCSessionDescription = function() {
            throw new DOMException('RTCSessionDescription is not supported', 'NotSupportedError');
        };

        // Block RTCIceCandidate
        window.RTCIceCandidate = function() {
            throw new DOMException('RTCIceCandidate is not supported', 'NotSupportedError');
        };
    } catch (e) {
        // WebRTC blocking failed - continue anyway
    }

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
        // Cache the base time on first call to simulate realistic page load times
        // Each metric is offset by realistic intervals from the base time
        const baseTime = Date.now() / 1000;
        const cachedTimes = {
            requestTime: baseTime - 0.8,                    // Request started ~800ms ago
            startLoadTime: baseTime - 0.7,                  // Started loading ~700ms ago
            commitLoadTime: baseTime - 0.5,                 // Committed ~500ms ago
            finishDocumentLoadTime: baseTime - 0.2,         // DOM finished ~200ms ago
            finishLoadTime: baseTime - 0.1,                 // Load finished ~100ms ago
            firstPaintTime: baseTime - 0.15,                // First paint ~150ms ago
            firstPaintAfterLoadTime: 0,
            navigationType: 'navigate',
            wasFetchedViaSpdy: false,
            wasNpnNegotiated: true,
            npnNegotiatedProtocol: 'h2',
            wasAlternateProtocolAvailable: false,
            connectionInfo: 'h2'
        };
        window.chrome.loadTimes = function() {
            return cachedTimes;
        };
    }

    // ========================================
    // 5. Mock permissions API
    // ========================================
    // Mock common permissions to avoid detection
    // Real browsers have specific default states for various permissions
    // Skip on about:blank as permissions API may not be available
    if (!isAboutBlank && window.navigator && window.navigator.permissions && typeof window.navigator.permissions.query === 'function') {
        const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
        const permissionDefaults = {
            'notifications': 'default',
            'geolocation': 'prompt',
            'camera': 'prompt',
            'microphone': 'prompt',
            'midi': 'prompt',
            'push': 'prompt',
            'background-sync': 'granted',
            'accelerometer': 'granted',
            'gyroscope': 'granted',
            'magnetometer': 'granted',
            'clipboard-read': 'prompt',
            'clipboard-write': 'granted',
            'payment-handler': 'prompt',
            'persistent-storage': 'prompt'
        };
        window.navigator.permissions.query = (parameters) => {
            const name = parameters && parameters.name;
            if (name && permissionDefaults.hasOwnProperty(name)) {
                return Promise.resolve({
                    state: permissionDefaults[name],
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
    try {
        // Check if already patched to avoid breaking on session reuse
        if (!Function.prototype.toString._stealth) {
            const originalFunctionToString = Function.prototype.toString;

            // Verify the original has .call method
            if (typeof originalFunctionToString !== 'function' || typeof originalFunctionToString.call !== 'function') {
                throw new Error('toString not patchable');
            }

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
                // Extra safety check before calling
                if (typeof originalFunctionToString === 'function' && typeof originalFunctionToString.call === 'function') {
                    return originalFunctionToString.call(this);
                }
                return '[native code]';
            };
            customFunctionToString._stealth = true;

            Object.defineProperty(Function.prototype, 'toString', {
                value: customFunctionToString,
                writable: true,
                configurable: true
            });
        }
    } catch (e) {
        // toString patching failed, continue anyway
    }

    // ========================================
    // 10. WebGL vendor/renderer
    // ========================================
    // Spoof WebGL to avoid detection of VM/headless
    // Using simple function wrapper instead of Proxy for better compatibility
    // Skip on about:blank as WebGL may not be available
    if (!isAboutBlank) try {
        const UNMASKED_VENDOR_WEBGL = 37445;
        const UNMASKED_RENDERER_WEBGL = 37446;

        ['WebGLRenderingContext', 'WebGL2RenderingContext'].forEach(function(ctxName) {
            try {
                const ctx = window[ctxName];
                if (!ctx || !ctx.prototype) return;

                // Safely get the original function
                const originalGetParameter = ctx.prototype.getParameter;
                if (!originalGetParameter || typeof originalGetParameter !== 'function') return;

                // Check if already wrapped
                if (originalGetParameter._stealth) return;

                // Store a reference to the original in a closure-safe way
                const origFn = originalGetParameter;

                // Create wrapper function
                ctx.prototype.getParameter = function(param) {
                    try {
                        if (param === UNMASKED_VENDOR_WEBGL) {
                            return 'Intel Inc.';
                        }
                        if (param === UNMASKED_RENDERER_WEBGL) {
                            return 'Intel Iris OpenGL Engine';
                        }
                        // Verify origFn is still valid before calling
                        // This prevents "Cannot read properties of undefined" errors
                        // when the page modifies Function.prototype
                        if (typeof origFn === 'function') {
                            return origFn.call(this, param);
                        }
                        return null;
                    } catch (e) {
                        return null;
                    }
                };
                ctx.prototype.getParameter._stealth = true;
            } catch (e) {
                // Skip this context
            }
        });
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

    // ========================================
    // 12. Canvas fingerprinting protection
    // ========================================
    // Add subtle noise to canvas APIs to prevent fingerprinting
    // while maintaining visual consistency for the same session.
    // Patches: toDataURL, toBlob, getImageData, WebGL readPixels
    // Skip on about:blank as canvas APIs may not be fully initialized
    if (!isAboutBlank) try {
        // Generate session-consistent seed if not already set
        if (!window.__canvasSeed) {
            window.__canvasSeed = Math.floor(Math.random() * 256);
        }
        const canvasSeed = window.__canvasSeed;

        // Helper function to apply consistent noise to pixel data
        // Uses seed to generate deterministic noise based on position
        const applyNoiseToImageData = function(data, width, height, seed) {
            // Apply noise to a subset of pixels (every 7th pixel to minimize visual impact)
            const step = 7;
            for (let i = 0; i < data.length; i += 4 * step) {
                // Generate position-based noise using seed
                const pixelIndex = i / 4;
                const noise = ((pixelIndex * 31 + seed) % 5) - 2; // Range: -2 to +2

                // Apply noise to RGB channels (not alpha)
                data[i] = Math.max(0, Math.min(255, data[i] + noise));         // R
                data[i + 1] = Math.max(0, Math.min(255, data[i + 1] + noise)); // G
                data[i + 2] = Math.max(0, Math.min(255, data[i + 2] + noise)); // B
            }
        };

        // 12a. Patch toDataURL
        const canvasToDataURL = HTMLCanvasElement.prototype.toDataURL;
        if (typeof canvasToDataURL === 'function' && !canvasToDataURL._stealth) {
            const originalToDataURL = canvasToDataURL;
            HTMLCanvasElement.prototype.toDataURL = function(type, quality) {
                try {
                    const ctx = this.getContext('2d');
                    if (ctx && this.width > 0 && this.height > 0) {
                        // Apply noise to multiple pixels
                        const width = Math.min(this.width, 16);
                        const height = Math.min(this.height, 16);
                        const imageData = ctx.getImageData(0, 0, width, height);
                        applyNoiseToImageData(imageData.data, width, height, canvasSeed);
                        ctx.putImageData(imageData, 0, 0);
                    }
                } catch (e) {
                    // Ignore canvas access errors (e.g., cross-origin tainted canvas)
                }
                return originalToDataURL.call(this, type, quality);
            };
            HTMLCanvasElement.prototype.toDataURL._stealth = true;
        }

        // 12b. Patch toBlob
        const canvasToBlob = HTMLCanvasElement.prototype.toBlob;
        if (typeof canvasToBlob === 'function' && !canvasToBlob._stealth) {
            const originalToBlob = canvasToBlob;
            HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
                try {
                    const ctx = this.getContext('2d');
                    if (ctx && this.width > 0 && this.height > 0) {
                        // Apply noise to multiple pixels
                        const width = Math.min(this.width, 16);
                        const height = Math.min(this.height, 16);
                        const imageData = ctx.getImageData(0, 0, width, height);
                        applyNoiseToImageData(imageData.data, width, height, canvasSeed);
                        ctx.putImageData(imageData, 0, 0);
                    }
                } catch (e) {
                    // Ignore canvas access errors
                }
                return originalToBlob.call(this, callback, type, quality);
            };
            HTMLCanvasElement.prototype.toBlob._stealth = true;
        }

        // 12c. Patch getImageData on CanvasRenderingContext2D
        const ctxGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        if (typeof ctxGetImageData === 'function' && !ctxGetImageData._stealth) {
            const originalGetImageData = ctxGetImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(sx, sy, sw, sh, settings) {
                const imageData = originalGetImageData.call(this, sx, sy, sw, sh, settings);
                try {
                    // Apply noise to returned data
                    applyNoiseToImageData(imageData.data, sw, sh, canvasSeed);
                } catch (e) {
                    // Ignore errors
                }
                return imageData;
            };
            CanvasRenderingContext2D.prototype.getImageData._stealth = true;
        }

        // 12d. Patch WebGL readPixels for both WebGL1 and WebGL2
        const webglContexts = ['WebGLRenderingContext', 'WebGL2RenderingContext'];
        webglContexts.forEach(function(ctxName) {
            try {
                const ctx = window[ctxName];
                if (!ctx || !ctx.prototype || !ctx.prototype.readPixels) return;
                if (ctx.prototype.readPixels._stealth) return;

                const originalReadPixels = ctx.prototype.readPixels;
                ctx.prototype.readPixels = function(x, y, width, height, format, type, pixels, dstOffset) {
                    // Call original first
                    if (arguments.length === 8) {
                        originalReadPixels.call(this, x, y, width, height, format, type, pixels, dstOffset);
                    } else {
                        originalReadPixels.call(this, x, y, width, height, format, type, pixels);
                    }

                    // Apply noise to the pixels array if it's a typed array
                    try {
                        if (pixels && pixels.length && typeof pixels[0] === 'number') {
                            const step = 7;
                            for (let i = 0; i < pixels.length; i += 4 * step) {
                                const pixelIndex = i / 4;
                                const noise = ((pixelIndex * 31 + canvasSeed) % 5) - 2;

                                // Apply noise to RGB (not alpha)
                                pixels[i] = Math.max(0, Math.min(255, pixels[i] + noise));
                                if (i + 1 < pixels.length) pixels[i + 1] = Math.max(0, Math.min(255, pixels[i + 1] + noise));
                                if (i + 2 < pixels.length) pixels[i + 2] = Math.max(0, Math.min(255, pixels[i + 2] + noise));
                            }
                        }
                    } catch (e) {
                        // Ignore errors
                    }
                };
                ctx.prototype.readPixels._stealth = true;
            } catch (e) {
                // Skip this context
            }
        });

    } catch (e) {
        // Canvas patching failed, continue
    }

    // ========================================
    // 13. AudioContext fingerprinting protection
    // ========================================
    // Override AudioContext to add noise to audio fingerprinting
    // Skip on about:blank as AudioContext may not be fully initialized
    if (!isAboutBlank) try {
        if (window.AudioContext && !window.AudioContext._stealth) {
            const OriginalAudioContext = window.AudioContext;
            window.AudioContext = function(...args) {
                const ctx = new OriginalAudioContext(...args);
                // Override createAnalyser to add subtle timing variations
                // Only patch if createAnalyser exists (may not on about:blank)
                if (ctx && typeof ctx.createAnalyser === 'function') {
                    const originalCreateAnalyser = ctx.createAnalyser.bind(ctx);
                    ctx.createAnalyser = function() {
                        const analyser = originalCreateAnalyser();
                        // Only patch if analyser has getFloatFrequencyData
                        if (analyser && typeof analyser.getFloatFrequencyData === 'function') {
                            const originalGetFloatFrequencyData = analyser.getFloatFrequencyData.bind(analyser);
                            analyser.getFloatFrequencyData = function(array) {
                                originalGetFloatFrequencyData(array);
                                // Add tiny random noise
                                for (let i = 0; i < array.length; i++) {
                                    array[i] += (Math.random() - 0.5) * 0.0001;
                                }
                            };
                        }
                        return analyser;
                    };
                }
                return ctx;
            };
            window.AudioContext._stealth = true;
            // Copy static properties
            Object.setPrototypeOf(window.AudioContext, OriginalAudioContext);
        }
    } catch (e) {
        // AudioContext patching failed, continue
    }

    // ========================================
    // 14. Battery API Mock
    // ========================================
    // Mock navigator.getBattery() to return consistent values
    // Some fingerprinting scripts use battery level to track users
    // Skip on about:blank as Battery API may not be available
    if (!isAboutBlank) try {
        if (navigator.getBattery && !navigator.getBattery._stealth) {
            // Generate session-consistent battery level (0.87-0.97)
            if (!window.__batteryLevel) {
                window.__batteryLevel = 0.87 + (Math.random() * 0.10);
            }

            const mockBatteryManager = {
                charging: true,
                chargingTime: 0,
                dischargingTime: Infinity,
                level: window.__batteryLevel,
                addEventListener: function(type, listener) {
                    // Store listeners but never fire them (battery doesn't change)
                },
                removeEventListener: function(type, listener) {},
                dispatchEvent: function(event) { return true; }
            };

            // Freeze to prevent modification detection
            Object.freeze(mockBatteryManager);

            navigator.getBattery = function() {
                return Promise.resolve(mockBatteryManager);
            };
            navigator.getBattery._stealth = true;

            // Make it look native
            Object.defineProperty(navigator.getBattery, 'toString', {
                value: function() { return 'function getBattery() { [native code] }'; },
                writable: false,
                configurable: false
            });
        }
    } catch (e) {
        // Battery API patching failed, continue
    }

    // ========================================
    // 15. Speech Synthesis Voice List
    // ========================================
    // Override speechSynthesis.getVoices() to return consistent Google voices
    // Fingerprinting can use voice list as an entropy source
    // Skip on about:blank as Speech Synthesis may not be available
    if (!isAboutBlank) try {
        // Check that speechSynthesis and getVoices exist before accessing _stealth
        if (window.speechSynthesis && typeof window.speechSynthesis.getVoices === 'function' && !window.speechSynthesis.getVoices._stealth) {
            const mockVoices = [
                { voiceURI: 'Google US English', name: 'Google US English', lang: 'en-US', localService: false, default: true },
                { voiceURI: 'Google UK English Female', name: 'Google UK English Female', lang: 'en-GB', localService: false, default: false },
                { voiceURI: 'Google UK English Male', name: 'Google UK English Male', lang: 'en-GB', localService: false, default: false },
                { voiceURI: 'Google Deutsch', name: 'Google Deutsch', lang: 'de-DE', localService: false, default: false },
                { voiceURI: 'Google español', name: 'Google español', lang: 'es-ES', localService: false, default: false },
                { voiceURI: 'Google français', name: 'Google français', lang: 'fr-FR', localService: false, default: false },
                { voiceURI: 'Google italiano', name: 'Google italiano', lang: 'it-IT', localService: false, default: false },
                { voiceURI: 'Google 日本語', name: 'Google 日本語', lang: 'ja-JP', localService: false, default: false },
                { voiceURI: 'Google 한국의', name: 'Google 한국의', lang: 'ko-KR', localService: false, default: false },
                { voiceURI: 'Google 中文（普通话）', name: 'Google 中文（普通话）', lang: 'zh-CN', localService: false, default: false }
            ].map(v => {
                // Freeze each voice object to prevent modification detection
                Object.freeze(v);
                return v;
            });

            const originalGetVoices = window.speechSynthesis.getVoices.bind(window.speechSynthesis);

            window.speechSynthesis.getVoices = function() {
                return mockVoices;
            };
            window.speechSynthesis.getVoices._stealth = true;

            // Handle onvoiceschanged - fire once to simulate voices loaded
            if (window.speechSynthesis.onvoiceschanged === null) {
                setTimeout(function() {
                    if (typeof window.speechSynthesis.onvoiceschanged === 'function') {
                        window.speechSynthesis.onvoiceschanged();
                    }
                }, 50);
            }
        }
    } catch (e) {
        // Speech synthesis patching failed, continue
    }

    // ========================================
    // 16. Font Enumeration Limiting
    // ========================================
    // Limit document.fonts API to prevent font-based fingerprinting
    // Real browsers have many fonts; headless often has few - we normalize
    // Skip on about:blank as document.fonts may not be available
    if (!isAboutBlank) try {
        // Check that document.fonts exists and has forEach method
        if (document.fonts && typeof document.fonts.forEach === 'function' && !document.fonts._stealthPatched) {
            const maxFonts = 50;
            const maxIterationFonts = 10;

            // Get original size value before overriding
            const originalSizeDescriptor = Object.getOwnPropertyDescriptor(FontFaceSet.prototype, 'size');
            const getOriginalSize = originalSizeDescriptor && originalSizeDescriptor.get
                ? originalSizeDescriptor.get.bind(document.fonts)
                : function() { return maxFonts; };

            // Override forEach to limit iterations
            const originalForEach = document.fonts.forEach.bind(document.fonts);
            document.fonts.forEach = function(callback, thisArg) {
                let count = 0;
                return originalForEach(function(font, key, parent) {
                    if (count < maxIterationFonts) {
                        callback.call(thisArg, font, key, parent);
                        count++;
                    }
                }, thisArg);
            };

            // Override size property to return capped value
            Object.defineProperty(document.fonts, 'size', {
                get: function() {
                    const realSize = getOriginalSize();
                    return Math.min(maxFonts, realSize);
                },
                configurable: true
            });

            document.fonts._stealthPatched = true;
        }
    } catch (e) {
        // Font enumeration patching failed, continue
    }

    // ========================================
    // 17. Timezone/Geolocation Consistency
    // ========================================
    // Override timezone APIs for consistent fingerprinting defense
    // Uses America/New_York as default, can be overridden via window.__stealthTimezone
    // Skip on about:blank as Intl may not be fully initialized
    if (!isAboutBlank) try {
        // Session timezone - default to America/New_York (offset 300 minutes = 5 hours)
        // Can be set via window.__stealthTimezone before stealth script runs
        const defaultTimezone = 'America/New_York';
        const defaultOffset = 300; // minutes (EST = UTC-5)

        const stealthTimezone = window.__stealthTimezone || defaultTimezone;
        const stealthOffset = window.__stealthTimezoneOffset !== undefined ? window.__stealthTimezoneOffset : defaultOffset;

        // Override getTimezoneOffset
        if (typeof Date.prototype.getTimezoneOffset === 'function' && !Date.prototype.getTimezoneOffset._stealth) {
            Date.prototype.getTimezoneOffset = function() {
                return stealthOffset;
            };
            Date.prototype.getTimezoneOffset._stealth = true;
        }

        // Override Intl.DateTimeFormat to return consistent timezone
        if (window.Intl && window.Intl.DateTimeFormat && !window.Intl.DateTimeFormat._stealth) {
            const OriginalDateTimeFormat = window.Intl.DateTimeFormat;

            window.Intl.DateTimeFormat = function(locales, options) {
                // Force our timezone if not explicitly set
                const opts = options ? Object.assign({}, options) : {};
                if (!opts.timeZone) {
                    opts.timeZone = stealthTimezone;
                }
                return new OriginalDateTimeFormat(locales, opts);
            };

            // Copy static methods and properties
            window.Intl.DateTimeFormat.supportedLocalesOf = OriginalDateTimeFormat.supportedLocalesOf;
            Object.setPrototypeOf(window.Intl.DateTimeFormat, OriginalDateTimeFormat);

            // Override resolvedOptions to return our timezone
            const originalResolvedOptions = OriginalDateTimeFormat.prototype.resolvedOptions;
            // Only patch if resolvedOptions exists and is a function
            if (typeof originalResolvedOptions === 'function') {
                OriginalDateTimeFormat.prototype.resolvedOptions = function() {
                    const resolved = originalResolvedOptions.call(this);
                    // If no explicit timezone was set, return our default
                    if (resolved && (resolved.timeZone === undefined || resolved.timeZone === 'UTC')) {
                        resolved.timeZone = stealthTimezone;
                    }
                    return resolved;
                };
            }

            window.Intl.DateTimeFormat._stealth = true;
        }
    } catch (e) {
        // Timezone patching failed, continue
    }

    } catch (e) {
        // Silently ignore patching failures - don't log to avoid detection
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
// Returns a cleanup function that MUST be called when the page is closed
// to prevent goroutine leaks from EachEvent listeners. The cleanup function
// is safe to call multiple times.
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

	// Create cancellable context for event listeners
	// This context is canceled when cleanup is called OR when parent context is done
	listenerCtx, cancel := context.WithCancel(ctx)
	pageWithCtx := page.Context(listenerCtx)

	// Fix #3: Add WaitGroup to track EachEvent goroutines to prevent leaks
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
				log.Debug().Msg("Resource blocking listeners cleaned up")
			case <-time.After(5 * time.Second):
				log.Warn().Msg("Timeout waiting for resource blocking listeners to cleanup")
			}
		})
	}

	// Monitor for page close to auto-cleanup goroutines
	// Fix CRITICAL #3: Don't call cleanupFunc from event handler to avoid deadlock.
	// cleanupFunc calls wg.Wait() which would wait for this goroutine to finish,
	// but this goroutine is waiting for cleanupFunc to complete - circular wait.
	// Instead, just cancel the context which signals all listeners to stop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		pageWithCtx.EachEvent(func(e *proto.TargetTargetDestroyed) bool {
			// Just cancel context - don't call cleanupFunc to avoid deadlock
			cancel()
			return true // Stop listening
		})()
	}()

	// Handle intercepted requests using Rod's EachEvent
	wg.Add(1)
	go func() {
		defer wg.Done()
		pageWithCtx.EachEvent(func(e *proto.FetchRequestPaused) bool {
			select {
			case <-listenerCtx.Done():
				return true // Stop listening
			default:
			}
			// Ignore error: request may have been canceled or page closed
			_ = proto.FetchFailRequest{
				RequestID:   e.RequestID,
				ErrorReason: proto.NetworkErrorReasonBlockedByClient,
			}.Call(page)
			return false // Continue listening
		})()
	}()

	return cleanupFunc, nil
}

// buildBlockPatterns creates the list of URL patterns to block.
// Pre-allocates capacity based on enabled flags to avoid reallocations.
func buildBlockPatterns(blockImages, blockCSS, blockFonts, blockMedia bool) []*proto.FetchRequestPattern {
	// Calculate capacity: images=8, css=1, fonts=5, media=5
	capacity := 0
	if blockImages {
		capacity += 8
	}
	if blockCSS {
		capacity++
	}
	if blockFonts {
		capacity += 5
	}
	if blockMedia {
		capacity += 5
	}
	patterns := make([]*proto.FetchRequestPattern, 0, capacity)

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

// SetUserAgent sets a custom user agent on the page with proper Client Hints.
// This is critical for bypassing Cloudflare detection which checks Sec-CH-UA headers.
func SetUserAgent(page *rod.Page, userAgent string) error {
	// Extract Chrome version from user agent for Client Hints
	// User agent format: ...Chrome/124.0.0.0...
	chromeVersion := "124"
	if idx := strings.Index(userAgent, "Chrome/"); idx != -1 {
		versionStart := idx + 7
		versionEnd := versionStart
		for versionEnd < len(userAgent) && userAgent[versionEnd] != '.' && userAgent[versionEnd] != ' ' {
			versionEnd++
		}
		if versionEnd > versionStart {
			chromeVersion = userAgent[versionStart:versionEnd]
		}
	}

	// Determine platform from user agent
	platform := "Linux"
	platformVersion := "6.5.0"
	architecture := "x86_64"
	if strings.Contains(userAgent, "Windows") {
		platform = "Windows"
		platformVersion = "15.0.0"
		architecture = "x86"
	} else if strings.Contains(userAgent, "Macintosh") {
		platform = "macOS"
		platformVersion = "14.0.0"
		architecture = "arm"
	}

	// Include "Google Chrome" brand to match real Chrome browsers
	// Real Chrome includes: "Not_A Brand", "Google Chrome", "Chromium"
	return proto.NetworkSetUserAgentOverride{
		UserAgent:      userAgent,
		AcceptLanguage: "en-US,en;q=0.9",
		Platform:       platform,
		UserAgentMetadata: &proto.EmulationUserAgentMetadata{
			Brands: []*proto.EmulationUserAgentBrandVersion{
				{Brand: "Not_A Brand", Version: "8"},
				{Brand: "Chromium", Version: chromeVersion},
				{Brand: "Google Chrome", Version: chromeVersion},
			},
			FullVersionList: []*proto.EmulationUserAgentBrandVersion{
				{Brand: "Not_A Brand", Version: "8.0.0.0"},
				{Brand: "Chromium", Version: chromeVersion + ".0.0.0"},
				{Brand: "Google Chrome", Version: chromeVersion + ".0.0.0"},
			},
			Platform:        platform,
			PlatformVersion: platformVersion,
			Architecture:    architecture,
			Model:           "",
			Mobile:          false,
			Bitness:         "64",
		},
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

// GetBrowserUserAgent retrieves the browser's actual user agent string.
// This is critical for anti-detection: we should use the browser's real UA
// instead of a hardcoded one, to prevent mismatches that Cloudflare can detect.
func GetBrowserUserAgent(page *rod.Page) (string, error) {
	result, err := page.Eval(`() => navigator.userAgent`)
	if err != nil {
		return "", fmt.Errorf("failed to get browser user agent: %w", err)
	}
	return result.Value.Str(), nil
}

// shadowInterceptScript intercepts Element.prototype.attachShadow to force
// all shadow roots to open mode. This allows JavaScript-based access to
// shadow DOM content that would otherwise be inaccessible in closed mode.
//
// DETECTION RISK: MEDIUM-HIGH
// This modifies a browser prototype, which can be detected by anti-bot systems
// that check for prototype tampering.
//
// Use this only as a fallback when CDP-native shadow root access fails.
const shadowInterceptScript = `
(() => {
    'use strict';

    // Skip if already applied
    if (window.__shadowInterceptApplied) {
        return;
    }
    window.__shadowInterceptApplied = true;

    try {
        // Store original attachShadow and Object.assign
        const originalAttachShadow = Element.prototype.attachShadow;
        // Cache Object.assign to prevent prototype pollution attacks
        const safeAssign = Object.assign.bind(Object);

        // Override attachShadow to force mode: 'open'
        Element.prototype.attachShadow = function(init) {
            // Force open mode using cached Object.assign
            // Create a plain object first to avoid prototype pollution
            const modifiedInit = safeAssign(Object.create(null), init, { mode: 'open' });
            return originalAttachShadow.call(this, modifiedInit);
        };

        // Make it look native
        Element.prototype.attachShadow.toString = function() {
            return 'function attachShadow() { [native code] }';
        };

    } catch (e) {
        // Silently ignore failures - don't log to avoid detection
    }
})();
`

// InjectShadowInterceptor injects the shadow root interception script into a page.
// This forces all future attachShadow calls to use mode: 'open', making shadow
// DOM content accessible via JavaScript.
//
// IMPORTANT: This should be called via Page.addScriptToEvaluateOnNewDocument
// to intercept before any page scripts run. Call this only when CDP-native
// shadow root access (via ShadowRoot()) has failed.
//
// Detection risk: MEDIUM-HIGH - modifies browser prototype
//
// Usage:
//
//	err := browser.InjectShadowInterceptor(page)
//	if err != nil {
//	    log.Warn().Err(err).Msg("Failed to inject shadow interceptor")
//	}
func InjectShadowInterceptor(page *rod.Page) error {
	// Use addScriptToEvaluateOnNewDocument so it runs before page scripts
	_, err := proto.PageAddScriptToEvaluateOnNewDocument{
		Source: shadowInterceptScript,
	}.Call(page)

	if err != nil {
		return fmt.Errorf("failed to inject shadow interceptor: %w", err)
	}

	log.Debug().Msg("Shadow root interceptor injected (forces mode: 'open')")
	return nil
}

// ApplyShadowInterceptorNow applies the shadow interception script immediately
// to the current page context. This is useful when the page has already loaded
// but you need to intercept future shadow roots.
//
// Note: This won't affect shadow roots that were already created before this call.
// For full coverage, use InjectShadowInterceptor before navigation.
func ApplyShadowInterceptorNow(page *rod.Page) error {
	_, err := page.Evaluate(rod.Eval(shadowInterceptScript))
	if err != nil {
		return fmt.Errorf("failed to apply shadow interceptor: %w", err)
	}

	log.Debug().Msg("Shadow root interceptor applied to current context")
	return nil
}

package browser

import (
	"fmt"

	"github.com/go-rod/rod"
	"github.com/go-rod/stealth"
	"github.com/rs/zerolog/log"
)

// Default viewport applied to every page.
const (
	DefaultViewportWidth  = 1920
	DefaultViewportHeight = 1080
)

// go-rod/stealth replaces navigator.languages with a fixed ['en-US', 'en'].
// Chrome's own value follows the configured language list, as the
// Accept-Language header does, so the fixed one contradicts the header for any
// other language. These two scripts run either side of go-rod/stealth: the
// first keeps Chrome's own property, the second puts it back. The holder
// property exists only between the two, before any page script runs.
const (
	keepNativeLanguagesScript = `(() => {
  try {
    const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages');
    if (d) Object.defineProperty(window, '__nativeLanguages', { value: d, configurable: true });
  } catch (e) {}
})();`

	restoreNativeLanguagesScript = `(() => {
  try {
    const d = window.__nativeLanguages;
    delete window.__nativeLanguages;
    if (d) Object.defineProperty(Navigator.prototype, 'languages', d);
  } catch (e) {}
})();`
)

// PageSetup holds the per-request values PreparePage applies to a page.
type PageSetup struct {
	// UserAgent is sent as the User-Agent header and reported by
	// navigator.userAgent. Empty leaves the browser's own value.
	UserAgent string

	// AcceptLanguages is the plain language list ("fr-FR,fr,en") behind the
	// Accept-Language header and navigator.languages. Empty means
	// DefaultAcceptLanguages.
	AcceptLanguages string

	// Timezone is an IANA timezone ID applied through CDP. Empty leaves the
	// browser's own timezone.
	Timezone string
}

// PreparePage applies the anti-detection setup to a blank page, before its
// first navigation. Stateless GET, stateless POST and session requests all go
// through it, so a site sees the same browser whichever way it is reached:
//
//  1. go-rod/stealth, registered to run at the start of every new document,
//     with navigator.languages left as Chrome reports it
//  2. the gate-2 corrections (WebGL renderer and screen geometry)
//  3. the timezone, through CDP
//  4. the user agent, with its client hints, platform and language list
//  5. the viewport
//
// Only a failure to register go-rod/stealth is returned: without it the page
// is trivially detected. The remaining steps log a warning and continue.
func PreparePage(page *rod.Page, setup PageSetup) error {
	if _, err := page.EvalOnNewDocument(keepNativeLanguagesScript); err != nil {
		log.Warn().Err(err).Msg("Failed to register navigator.languages script")
	}
	if _, err := page.EvalOnNewDocument(stealth.JS); err != nil {
		return fmt.Errorf("failed to register stealth script: %w", err)
	}
	if _, err := page.EvalOnNewDocument(restoreNativeLanguagesScript); err != nil {
		log.Warn().Err(err).Msg("Failed to register navigator.languages script")
	}

	if err := ApplyGate2Corrections(page); err != nil {
		log.Warn().Err(err).Msg("Failed to apply gate-2 fingerprint corrections")
	}

	if setup.Timezone != "" {
		if err := ApplyTimezoneOverride(page, setup.Timezone); err != nil {
			log.Warn().Err(err).Str("timezone", setup.Timezone).Msg("Failed to apply timezone override")
		}
	}

	if setup.UserAgent != "" {
		if err := SetUserAgent(page, setup.UserAgent, setup.AcceptLanguages); err != nil {
			log.Warn().Err(err).Msg("Failed to set user agent")
		}
	}

	if err := SetViewport(page, DefaultViewportWidth, DefaultViewportHeight); err != nil {
		log.Warn().Err(err).Msg("Failed to set viewport")
	}

	return nil
}

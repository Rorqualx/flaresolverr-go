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

// PageSetup holds the per-request values PreparePage applies to a page.
type PageSetup struct {
	// UserAgent is sent as the User-Agent header and reported by
	// navigator.userAgent. Empty leaves the browser's own value.
	UserAgent string

	// Timezone is an IANA timezone ID applied through CDP. Empty leaves the
	// browser's own timezone.
	Timezone string
}

// PreparePage applies the anti-detection setup to a blank page, before its
// first navigation. Stateless GET, stateless POST and session requests all go
// through it, so a site sees the same browser whichever way it is reached:
//
//  1. go-rod/stealth, registered to run at the start of every new document
//  2. the gate-2 corrections (WebGL renderer and screen geometry)
//  3. the timezone, through CDP
//  4. the user agent and its client hints
//  5. the viewport
//
// Only a failure to register go-rod/stealth is returned: without it the page
// is trivially detected. The remaining steps log a warning and continue.
func PreparePage(page *rod.Page, setup PageSetup) error {
	if _, err := page.EvalOnNewDocument(stealth.JS); err != nil {
		return fmt.Errorf("failed to register stealth script: %w", err)
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
		if err := SetUserAgent(page, setup.UserAgent); err != nil {
			log.Warn().Err(err).Msg("Failed to set user agent")
		}
	}

	if err := SetViewport(page, DefaultViewportWidth, DefaultViewportHeight); err != nil {
		log.Warn().Err(err).Msg("Failed to set viewport")
	}

	return nil
}

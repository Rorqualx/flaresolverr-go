package browser

import (
	"fmt"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// ApplyTimezoneOverride applies a per-page timezone override via Chrome DevTools Protocol.
// It works regardless of which stealth library wired the page, because the override is
// applied at the browser layer before any JavaScript runs. An empty tz is a no-op.
func ApplyTimezoneOverride(page *rod.Page, tz string) error {
	if tz == "" {
		return nil
	}
	if err := (proto.EmulationSetTimezoneOverride{TimezoneID: tz}).Call(page); err != nil {
		return fmt.Errorf("set timezone override %q: %w", tz, err)
	}
	return nil
}

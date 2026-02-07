package humanize

import (
	"context"
	"math"
	"math/rand"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// ScrollConfig contains configuration for humanized scroll behavior.
type ScrollConfig struct {
	// MinScrollSteps is the minimum number of scroll increments for smooth scrolling.
	MinScrollSteps int
	// MaxScrollSteps is the maximum number of scroll increments.
	MaxScrollSteps int
	// MinStepDelayMs is the minimum delay between scroll steps.
	MinStepDelayMs int
	// MaxStepDelayMs is the maximum delay between scroll steps.
	MaxStepDelayMs int
	// ScrollMargin is the margin to add when scrolling element into view (pixels).
	ScrollMargin float64
	// PreScrollDelayMinMs is the delay before starting to scroll.
	PreScrollDelayMinMs int
	PreScrollDelayMaxMs int
	// PostScrollDelayMinMs is the delay after completing scroll.
	PostScrollDelayMinMs int
	PostScrollDelayMaxMs int
}

// DefaultScrollConfig returns sensible defaults for human-like scrolling.
func DefaultScrollConfig() ScrollConfig {
	return ScrollConfig{
		MinScrollSteps:       8,
		MaxScrollSteps:       20,
		MinStepDelayMs:       20,
		MaxStepDelayMs:       60,
		ScrollMargin:         100,
		PreScrollDelayMinMs:  50,
		PreScrollDelayMaxMs:  200,
		PostScrollDelayMinMs: 100,
		PostScrollDelayMaxMs: 300,
	}
}

// Scroller provides humanized scroll interactions for a browser page.
type Scroller struct {
	page   *rod.Page
	config ScrollConfig
}

// NewScroller creates a new humanized scroller for the given page.
func NewScroller(page *rod.Page) *Scroller {
	return &Scroller{
		page:   page,
		config: DefaultScrollConfig(),
	}
}

// NewScrollerWithConfig creates a new humanized scroller with custom config.
func NewScrollerWithConfig(page *rod.Page, config ScrollConfig) *Scroller {
	return &Scroller{
		page:   page,
		config: config,
	}
}

// ScrollToElement smoothly scrolls to bring an element into view.
// Uses incremental scrolling with easing for natural appearance.
func (s *Scroller) ScrollToElement(ctx context.Context, element *rod.Element) error {
	// Get element bounds
	shape, err := element.Shape()
	if err != nil {
		return err
	}

	if shape == nil || len(shape.Quads) == 0 {
		return ErrElementNotVisible
	}

	// Get viewport info
	layoutMetrics, err := proto.PageGetLayoutMetrics{}.Call(s.page)
	if err != nil {
		return err
	}

	// Calculate element center Y position
	quad := shape.Quads[0]
	elementCenterY := (quad[1] + quad[3] + quad[5] + quad[7]) / 4

	// Get current scroll position and viewport height
	currentScrollY := layoutMetrics.VisualViewport.PageY
	viewportHeight := layoutMetrics.VisualViewport.ClientHeight

	// Calculate if element is in view
	viewportTop := currentScrollY
	viewportBottom := currentScrollY + viewportHeight

	// Check if element is already in view (with margin)
	if elementCenterY >= viewportTop+s.config.ScrollMargin &&
		elementCenterY <= viewportBottom-s.config.ScrollMargin {
		log.Debug().Msg("Element already in view, no scroll needed")
		return nil
	}

	// Calculate target scroll position (center element in viewport)
	targetScrollY := elementCenterY - viewportHeight/2

	// Clamp to valid scroll range
	maxScrollY := layoutMetrics.ContentSize.Height - viewportHeight
	if targetScrollY < 0 {
		targetScrollY = 0
	}
	if targetScrollY > maxScrollY {
		targetScrollY = maxScrollY
	}

	// Perform smooth scroll
	return s.smoothScrollTo(ctx, currentScrollY, targetScrollY)
}

// ScrollBy scrolls the page by the specified delta with smooth animation.
func (s *Scroller) ScrollBy(ctx context.Context, deltaY float64) error {
	// Get current scroll position
	layoutMetrics, err := proto.PageGetLayoutMetrics{}.Call(s.page)
	if err != nil {
		return err
	}

	currentScrollY := layoutMetrics.VisualViewport.PageY
	targetScrollY := currentScrollY + deltaY

	// Clamp to valid range
	maxScrollY := layoutMetrics.ContentSize.Height - layoutMetrics.VisualViewport.ClientHeight
	if targetScrollY < 0 {
		targetScrollY = 0
	}
	if targetScrollY > maxScrollY {
		targetScrollY = maxScrollY
	}

	return s.smoothScrollTo(ctx, currentScrollY, targetScrollY)
}

// ScrollToTop smoothly scrolls to the top of the page.
func (s *Scroller) ScrollToTop(ctx context.Context) error {
	layoutMetrics, err := proto.PageGetLayoutMetrics{}.Call(s.page)
	if err != nil {
		return err
	}

	currentScrollY := layoutMetrics.VisualViewport.PageY
	if currentScrollY < 10 {
		return nil // Already at top
	}

	return s.smoothScrollTo(ctx, currentScrollY, 0)
}

// ScrollToBottom smoothly scrolls to the bottom of the page.
func (s *Scroller) ScrollToBottom(ctx context.Context) error {
	layoutMetrics, err := proto.PageGetLayoutMetrics{}.Call(s.page)
	if err != nil {
		return err
	}

	currentScrollY := layoutMetrics.VisualViewport.PageY
	maxScrollY := layoutMetrics.ContentSize.Height - layoutMetrics.VisualViewport.ClientHeight

	if maxScrollY-currentScrollY < 10 {
		return nil // Already at bottom
	}

	return s.smoothScrollTo(ctx, currentScrollY, maxScrollY)
}

// smoothScrollTo performs a smooth scroll animation from current to target Y position.
func (s *Scroller) smoothScrollTo(ctx context.Context, fromY, toY float64) error {
	// Pre-scroll delay
	preDelay := RandomDuration(s.config.PreScrollDelayMinMs, s.config.PreScrollDelayMaxMs)
	if !sleepWithContext(ctx, preDelay) {
		return ctx.Err()
	}

	// Calculate scroll distance and steps
	distance := math.Abs(toY - fromY)
	if distance < 1 {
		return nil
	}

	// Number of steps scales with distance
	numSteps := s.config.MinScrollSteps + int(distance/100)
	if numSteps > s.config.MaxScrollSteps {
		numSteps = s.config.MaxScrollSteps
	}

	log.Debug().
		Float64("from_y", fromY).
		Float64("to_y", toY).
		Int("steps", numSteps).
		Msg("Starting smooth scroll")

	// Generate scroll positions with easing
	for i := 1; i <= numSteps; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Apply easing function for natural movement
		t := float64(i) / float64(numSteps)
		easedT := easeOutCubic(t)

		// Calculate current scroll position
		currentY := fromY + (toY-fromY)*easedT

		// Execute scroll via JavaScript
		_, err := s.page.Eval(`window.scrollTo({top: arguments[0], behavior: 'instant'})`, currentY)
		if err != nil {
			log.Debug().Err(err).Msg("Scroll step failed")
			// Continue anyway, might still work
		}

		// Delay between steps
		stepDelay := RandomDuration(s.config.MinStepDelayMs, s.config.MaxStepDelayMs)
		if !sleepWithContext(ctx, stepDelay) {
			return ctx.Err()
		}
	}

	// Post-scroll delay
	postDelay := RandomDuration(s.config.PostScrollDelayMinMs, s.config.PostScrollDelayMaxMs)
	if !sleepWithContext(ctx, postDelay) {
		return ctx.Err()
	}

	log.Debug().Float64("target_y", toY).Msg("Smooth scroll completed")
	return nil
}

// easeOutCubic provides deceleration easing for natural scroll ending.
func easeOutCubic(t float64) float64 {
	return 1 - math.Pow(1-t, 3)
}

// RandomSmallScroll performs a small random scroll to simulate natural page exploration.
// This can be used before clicking to appear more human-like.
func (s *Scroller) RandomSmallScroll(ctx context.Context) error {
	// Random scroll amount between -50 and +50 pixels
	delta := float64(rand.Intn(101) - 50)
	if math.Abs(delta) < 10 {
		// Skip very small scrolls
		return nil
	}

	log.Debug().Float64("delta", delta).Msg("Performing random small scroll")
	return s.ScrollBy(ctx, delta)
}

// EnsureElementVisible scrolls if necessary to ensure element is visible.
// Returns true if scrolling was performed, false if element was already visible.
func (s *Scroller) EnsureElementVisible(ctx context.Context, element *rod.Element) (bool, error) {
	// Get element bounds
	shape, err := element.Shape()
	if err != nil {
		return false, err
	}

	if shape == nil || len(shape.Quads) == 0 {
		return false, ErrElementNotVisible
	}

	// Get viewport info
	layoutMetrics, err := proto.PageGetLayoutMetrics{}.Call(s.page)
	if err != nil {
		return false, err
	}

	// Calculate element position
	quad := shape.Quads[0]
	elementTop := quad[1]
	elementBottom := quad[5]

	// Get viewport bounds
	viewportTop := layoutMetrics.VisualViewport.PageY
	viewportBottom := viewportTop + layoutMetrics.VisualViewport.ClientHeight

	// Check if element is fully visible
	isVisible := elementTop >= viewportTop+s.config.ScrollMargin &&
		elementBottom <= viewportBottom-s.config.ScrollMargin

	if isVisible {
		return false, nil
	}

	// Element needs scrolling
	if err := s.ScrollToElement(ctx, element); err != nil {
		return false, err
	}

	return true, nil
}

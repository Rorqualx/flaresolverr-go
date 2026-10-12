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

	// The quad is relative to the viewport, not to the page.
	quad := shape.Quads[0]
	elementCenterY := (quad[1] + quad[3] + quad[5] + quad[7]) / 4

	// Get current scroll position and viewport height
	currentScrollY := layoutMetrics.VisualViewport.PageY
	viewportHeight := layoutMetrics.VisualViewport.ClientHeight

	// Check if element is already in view (with margin)
	if inViewport(elementCenterY, elementCenterY, viewportHeight, s.config.ScrollMargin) {
		log.Debug().Msg("Element already in view, no scroll needed")
		return nil
	}

	// Scroll so the element's center is in the middle of the viewport
	target := targetScrollY(elementCenterY, currentScrollY, viewportHeight, layoutMetrics.ContentSize.Height)

	// Perform smooth scroll
	return s.smoothScrollTo(ctx, currentScrollY, target)
}

// inViewport reports whether the span from top to bottom lies inside the
// viewport, at least margin away from its top and bottom edges. top and bottom
// are relative to the viewport, as element quads are: 0 is the viewport's top
// edge, whatever the page's scroll position.
func inViewport(top, bottom, viewportHeight, margin float64) bool {
	return top >= margin && bottom <= viewportHeight-margin
}

// targetScrollY returns the page scroll position that puts a point in the
// middle of the viewport. centerY is the point's position relative to the
// viewport; scrollY is the current scroll position. The result is clamped to
// the range the page can scroll.
func targetScrollY(centerY, scrollY, viewportHeight, contentHeight float64) float64 {
	return clampScrollY(scrollY+centerY-viewportHeight/2, viewportHeight, contentHeight)
}

// clampScrollY limits a scroll position to the range the page can scroll:
// 0 to contentHeight-viewportHeight, or just 0 when the content is shorter
// than the viewport.
func clampScrollY(y, viewportHeight, contentHeight float64) float64 {
	maxScrollY := contentHeight - viewportHeight
	if y > maxScrollY {
		y = maxScrollY
	}
	if y < 0 {
		y = 0
	}
	return y
}

// ScrollBy scrolls the page by the specified delta with smooth animation.
func (s *Scroller) ScrollBy(ctx context.Context, deltaY float64) error {
	// Get current scroll position
	layoutMetrics, err := proto.PageGetLayoutMetrics{}.Call(s.page)
	if err != nil {
		return err
	}

	currentScrollY := layoutMetrics.VisualViewport.PageY
	target := clampScrollY(currentScrollY+deltaY, layoutMetrics.VisualViewport.ClientHeight, layoutMetrics.ContentSize.Height)

	return s.smoothScrollTo(ctx, currentScrollY, target)
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

		// Execute scroll via JavaScript. Eval calls what it is given as a
		// function, so this must be one: a bare statement is not callable and
		// every step failed.
		_, err := s.page.Eval(`(y) => window.scrollTo({top: y, behavior: 'instant'})`, currentY)
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

	// The quad is relative to the viewport, not to the page.
	quad := shape.Quads[0]
	elementTop := quad[1]
	elementBottom := quad[5]

	// Check if element is fully visible
	if inViewport(elementTop, elementBottom, layoutMetrics.VisualViewport.ClientHeight, s.config.ScrollMargin) {
		return false, nil
	}

	// Element needs scrolling
	if err := s.ScrollToElement(ctx, element); err != nil {
		return false, err
	}

	return true, nil
}

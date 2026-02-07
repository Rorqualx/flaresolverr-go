// Package humanize provides human-like interaction patterns for browser automation.
// It implements behavioral simulation to avoid bot detection including:
// - Bezier curve mouse movements that mimic human neuromotor patterns
// - Randomized click positions within target bounds
// - Natural timing variations for all interactions
package humanize

import (
	"context"
	"math"
	"math/rand"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// Point represents a 2D coordinate.
type Point struct {
	X, Y float64
}

// MouseConfig contains configuration for humanized mouse behavior.
type MouseConfig struct {
	// MinSteps is the minimum number of points in a mouse movement path.
	MinSteps int
	// MaxSteps is the maximum number of points in a mouse movement path.
	MaxSteps int
	// MinStepDelayMs is the minimum delay between movement steps in milliseconds.
	MinStepDelayMs int
	// MaxStepDelayMs is the maximum delay between movement steps in milliseconds.
	MaxStepDelayMs int
	// ClickOffsetRadius is the maximum random offset from center when clicking (pixels).
	ClickOffsetRadius float64
	// PreClickHoverMs is the delay to hover before clicking (min, max).
	PreClickHoverMinMs int
	PreClickHoverMaxMs int
	// PostClickDwellMs is the delay to dwell after clicking (min, max).
	PostClickDwellMinMs int
	PostClickDwellMaxMs int
}

// DefaultMouseConfig returns sensible defaults for human-like mouse behavior.
func DefaultMouseConfig() MouseConfig {
	return MouseConfig{
		MinSteps:            15,
		MaxSteps:            30,
		MinStepDelayMs:      3,
		MaxStepDelayMs:      12,
		ClickOffsetRadius:   5.0,
		PreClickHoverMinMs:  50,
		PreClickHoverMaxMs:  200,
		PostClickDwellMinMs: 80,
		PostClickDwellMaxMs: 250,
	}
}

// Mouse provides humanized mouse interactions for a browser page.
type Mouse struct {
	page   *rod.Page
	config MouseConfig
}

// NewMouse creates a new humanized mouse controller for the given page.
func NewMouse(page *rod.Page) *Mouse {
	return &Mouse{
		page:   page,
		config: DefaultMouseConfig(),
	}
}

// NewMouseWithConfig creates a new humanized mouse controller with custom config.
func NewMouseWithConfig(page *rod.Page, config MouseConfig) *Mouse {
	return &Mouse{
		page:   page,
		config: config,
	}
}

// MoveTo moves the mouse to the target coordinates using Bezier curve interpolation.
// The movement mimics human neuromotor patterns with natural acceleration/deceleration.
func (m *Mouse) MoveTo(ctx context.Context, x, y float64) error {
	// Get current mouse position
	currentPos := m.page.Mouse.Position()
	start := Point{X: currentPos.X, Y: currentPos.Y}
	end := Point{X: x, Y: y}

	// Generate Bezier path
	numSteps := m.config.MinSteps + rand.Intn(m.config.MaxSteps-m.config.MinSteps+1)
	path := generateBezierPath(start, end, numSteps)

	// Move through each point with random delays
	for _, p := range path {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := m.page.Mouse.MoveTo(proto.NewPoint(p.X, p.Y)); err != nil {
			return err
		}

		// Random delay between steps
		delay := RandomDuration(m.config.MinStepDelayMs, m.config.MaxStepDelayMs)
		if !sleepWithContext(ctx, delay) {
			return ctx.Err()
		}
	}

	return nil
}

// Click performs a humanized click at the target coordinates.
// Includes movement to target, pre-click hover, click, and post-click dwell.
func (m *Mouse) Click(ctx context.Context, x, y float64) error {
	// Add random offset within click radius for natural variation
	offsetX := (rand.Float64()*2 - 1) * m.config.ClickOffsetRadius
	offsetY := (rand.Float64()*2 - 1) * m.config.ClickOffsetRadius
	targetX := x + offsetX
	targetY := y + offsetY

	// Move to target with Bezier curve
	if err := m.MoveTo(ctx, targetX, targetY); err != nil {
		return err
	}

	// Pre-click hover delay
	hoverDelay := RandomDuration(m.config.PreClickHoverMinMs, m.config.PreClickHoverMaxMs)
	if !sleepWithContext(ctx, hoverDelay) {
		return ctx.Err()
	}

	// Perform click
	if err := m.page.Mouse.Click(proto.InputMouseButtonLeft, 1); err != nil {
		return err
	}

	// Post-click dwell time
	dwellDelay := RandomDuration(m.config.PostClickDwellMinMs, m.config.PostClickDwellMaxMs)
	if !sleepWithContext(ctx, dwellDelay) {
		return ctx.Err()
	}

	log.Debug().
		Float64("x", targetX).
		Float64("y", targetY).
		Msg("Humanized click completed")

	return nil
}

// ClickElement performs a humanized click on the center of a DOM element.
// Returns error if element cannot be found or clicked.
func (m *Mouse) ClickElement(ctx context.Context, element *rod.Element) error {
	// Get element shape/bounds
	shape, err := element.Shape()
	if err != nil {
		return err
	}

	if shape == nil || len(shape.Quads) == 0 {
		return ErrElementNotVisible
	}

	// Calculate center of element
	quad := shape.Quads[0]
	centerX := (quad[0] + quad[2] + quad[4] + quad[6]) / 4
	centerY := (quad[1] + quad[3] + quad[5] + quad[7]) / 4

	return m.Click(ctx, centerX, centerY)
}

// ClickWithinBounds clicks at a random position within the given bounds.
// This is useful for clicking checkboxes or buttons where exact position doesn't matter.
func (m *Mouse) ClickWithinBounds(ctx context.Context, bounds *proto.DOMRect) error {
	// Calculate a random position within the bounds
	// Avoid edges by using 20%-80% of the area
	marginX := bounds.Width * 0.2
	marginY := bounds.Height * 0.2

	targetX := bounds.X + marginX + rand.Float64()*(bounds.Width-2*marginX)
	targetY := bounds.Y + marginY + rand.Float64()*(bounds.Height-2*marginY)

	return m.Click(ctx, targetX, targetY)
}

// generateBezierPath generates a Bezier curve path between two points.
// Uses cubic Bezier with randomized control points for natural movement.
func generateBezierPath(start, end Point, numPoints int) []Point {
	if numPoints < 2 {
		numPoints = 2
	}

	// Calculate distance and angle for control point placement
	dx := end.X - start.X
	dy := end.Y - start.Y
	distance := math.Sqrt(dx*dx + dy*dy)

	// Generate control points with randomized offset
	// Control points are placed perpendicular to the line between start and end
	// with some randomization for natural-looking curves
	ctrl1Offset := distance * (0.2 + rand.Float64()*0.3)
	ctrl2Offset := distance * (0.2 + rand.Float64()*0.3)

	// Random perpendicular direction (left or right of path)
	perpDir1 := 1.0
	if rand.Float64() < 0.5 {
		perpDir1 = -1.0
	}
	perpDir2 := 1.0
	if rand.Float64() < 0.5 {
		perpDir2 = -1.0
	}

	// Calculate perpendicular vector (normalized)
	perpX := -dy / distance
	perpY := dx / distance
	if distance == 0 {
		perpX, perpY = 0, 0
	}

	// Control point 1: 1/3 along the path
	ctrl1 := Point{
		X: start.X + dx*0.33 + perpX*ctrl1Offset*perpDir1,
		Y: start.Y + dy*0.33 + perpY*ctrl1Offset*perpDir1,
	}

	// Control point 2: 2/3 along the path
	ctrl2 := Point{
		X: start.X + dx*0.67 + perpX*ctrl2Offset*perpDir2,
		Y: start.Y + dy*0.67 + perpY*ctrl2Offset*perpDir2,
	}

	// Generate points along the Bezier curve
	points := make([]Point, numPoints)
	for i := 0; i < numPoints; i++ {
		t := float64(i) / float64(numPoints-1)

		// Apply easing function for natural acceleration/deceleration
		// Using ease-in-out cubic for human-like movement
		t = easeInOutCubic(t)

		// Cubic Bezier formula
		mt := 1 - t
		mt2 := mt * mt
		mt3 := mt2 * mt
		t2 := t * t
		t3 := t2 * t

		points[i] = Point{
			X: mt3*start.X + 3*mt2*t*ctrl1.X + 3*mt*t2*ctrl2.X + t3*end.X,
			Y: mt3*start.Y + 3*mt2*t*ctrl1.Y + 3*mt*t2*ctrl2.Y + t3*end.Y,
		}
	}

	return points
}

// easeInOutCubic applies cubic easing for natural acceleration/deceleration.
// Returns a value between 0 and 1 that starts slow, speeds up, then slows down.
func easeInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	return 1 - math.Pow(-2*t+2, 3)/2
}

// GetPosition returns the current mouse position.
func (m *Mouse) GetPosition() Point {
	pos := m.page.Mouse.Position()
	return Point{X: pos.X, Y: pos.Y}
}

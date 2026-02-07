package humanize

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

// Common errors for the humanize package.
var (
	// ErrElementNotVisible is returned when an element cannot be found or has no visible bounds.
	ErrElementNotVisible = errors.New("element not visible or has no bounds")
)

// TimingConfig contains configuration for humanized timing behavior.
type TimingConfig struct {
	// Poll interval range (milliseconds)
	PollIntervalMinMs int
	PollIntervalMaxMs int

	// Pre-action delays (milliseconds)
	PreActionDelayMinMs int
	PreActionDelayMaxMs int

	// Post-action delays (milliseconds)
	PostActionDelayMinMs int
	PostActionDelayMaxMs int

	// Typing delays (milliseconds per character)
	TypingDelayMinMs int
	TypingDelayMaxMs int
}

// DefaultTimingConfig returns sensible defaults for human-like timing.
func DefaultTimingConfig() TimingConfig {
	return TimingConfig{
		PollIntervalMinMs:    800,
		PollIntervalMaxMs:    1500,
		PreActionDelayMinMs:  100,
		PreActionDelayMaxMs:  400,
		PostActionDelayMinMs: 150,
		PostActionDelayMaxMs: 500,
		TypingDelayMinMs:     50,
		TypingDelayMaxMs:     150,
	}
}

// Timing provides humanized timing utilities.
type Timing struct {
	config TimingConfig
}

// NewTiming creates a new timing utility with default config.
func NewTiming() *Timing {
	return &Timing{
		config: DefaultTimingConfig(),
	}
}

// NewTimingWithConfig creates a new timing utility with custom config.
func NewTimingWithConfig(config TimingConfig) *Timing {
	return &Timing{
		config: config,
	}
}

// RandomPollInterval returns a random duration between 0.8s and 1.5s.
// This replaces the fixed 1-second poll interval in the solver loop.
func (t *Timing) RandomPollInterval() time.Duration {
	return RandomDuration(t.config.PollIntervalMinMs, t.config.PollIntervalMaxMs)
}

// PreActionDelay returns a random delay to use before performing an action.
// Simulates the natural pause before a human takes action.
func (t *Timing) PreActionDelay() time.Duration {
	return RandomDuration(t.config.PreActionDelayMinMs, t.config.PreActionDelayMaxMs)
}

// PostActionDelay returns a random delay to use after performing an action.
// Simulates the natural dwell time after a human completes an action.
func (t *Timing) PostActionDelay() time.Duration {
	return RandomDuration(t.config.PostActionDelayMinMs, t.config.PostActionDelayMaxMs)
}

// TypingDelay returns a random delay between keystrokes.
// Simulates natural typing speed variations.
func (t *Timing) TypingDelay() time.Duration {
	return RandomDuration(t.config.TypingDelayMinMs, t.config.TypingDelayMaxMs)
}

// RandomDuration returns a random duration between min and max milliseconds.
func RandomDuration(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	ms := minMs + rand.Intn(maxMs-minMs+1)
	return time.Duration(ms) * time.Millisecond
}

// RandomPollInterval returns a random poll interval between 0.8s and 1.5s.
// This is a convenience function for the most common use case.
func RandomPollInterval() time.Duration {
	return RandomDuration(800, 1500)
}

// sleepWithContext sleeps for the specified duration or until context is canceled.
// Returns true if the sleep completed normally, false if interrupted.
// Uses time.NewTimer instead of time.After to prevent timer leak.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// SleepWithContext is the exported version of sleepWithContext.
// Sleeps for the specified duration or until context is canceled.
// Returns true if the sleep completed normally, false if interrupted.
func SleepWithContext(ctx context.Context, d time.Duration) bool {
	return sleepWithContext(ctx, d)
}

// SleepWithJitter sleeps for the given duration plus/minus a random jitter.
// jitterPercent is the maximum jitter as a percentage (0.0 to 1.0).
// For example, SleepWithJitter(ctx, 1*time.Second, 0.2) sleeps for 0.8s-1.2s.
func SleepWithJitter(ctx context.Context, base time.Duration, jitterPercent float64) bool {
	if jitterPercent < 0 {
		jitterPercent = 0
	}
	if jitterPercent > 1 {
		jitterPercent = 1
	}

	// Calculate jitter range
	jitterRange := float64(base) * jitterPercent
	jitter := (rand.Float64()*2 - 1) * jitterRange // -jitterRange to +jitterRange

	duration := time.Duration(float64(base) + jitter)
	if duration < 0 {
		duration = 0
	}

	return sleepWithContext(ctx, duration)
}

// WaitWithContext waits for the given duration, respecting context cancellation.
// This is an alias for SleepWithContext for semantic clarity.
func WaitWithContext(ctx context.Context, d time.Duration) bool {
	return sleepWithContext(ctx, d)
}

// RandomWait waits for a random duration between min and max.
func RandomWait(ctx context.Context, minMs, maxMs int) bool {
	return sleepWithContext(ctx, RandomDuration(minMs, maxMs))
}

// HumanDelay returns a human-like delay based on the action type.
// Action types: "click", "scroll", "navigate", "type"
func HumanDelay(action string) time.Duration {
	switch action {
	case "click":
		return RandomDuration(100, 300)
	case "scroll":
		return RandomDuration(200, 500)
	case "navigate":
		return RandomDuration(500, 1000)
	case "type":
		return RandomDuration(50, 150)
	default:
		return RandomDuration(100, 300)
	}
}

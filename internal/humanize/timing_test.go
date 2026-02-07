package humanize

import (
	"context"
	"testing"
	"time"
)

func TestRandomDuration(t *testing.T) {
	tests := []struct {
		name   string
		minMs  int
		maxMs  int
		minExp time.Duration
		maxExp time.Duration
	}{
		{
			name:   "typical range",
			minMs:  100,
			maxMs:  500,
			minExp: 100 * time.Millisecond,
			maxExp: 500 * time.Millisecond,
		},
		{
			name:   "same min max",
			minMs:  200,
			maxMs:  200,
			minExp: 200 * time.Millisecond,
			maxExp: 200 * time.Millisecond,
		},
		{
			name:   "zero min",
			minMs:  0,
			maxMs:  100,
			minExp: 0,
			maxExp: 100 * time.Millisecond,
		},
		{
			name:   "inverted range returns min",
			minMs:  500,
			maxMs:  100,
			minExp: 500 * time.Millisecond,
			maxExp: 500 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run multiple times to test randomness
			for i := 0; i < 100; i++ {
				got := RandomDuration(tt.minMs, tt.maxMs)
				if got < tt.minExp || got > tt.maxExp {
					t.Errorf("RandomDuration(%d, %d) = %v, want between %v and %v",
						tt.minMs, tt.maxMs, got, tt.minExp, tt.maxExp)
				}
			}
		})
	}
}

func TestRandomPollInterval(t *testing.T) {
	minExpected := 800 * time.Millisecond
	maxExpected := 1500 * time.Millisecond

	// Run multiple times to test randomness
	for i := 0; i < 100; i++ {
		got := RandomPollInterval()
		if got < minExpected || got > maxExpected {
			t.Errorf("RandomPollInterval() = %v, want between %v and %v",
				got, minExpected, maxExpected)
		}
	}
}

func TestSleepWithContext_Completes(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	completed := SleepWithContext(ctx, 50*time.Millisecond)
	elapsed := time.Since(start)

	if !completed {
		t.Error("SleepWithContext should return true when sleep completes")
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("SleepWithContext returned too quickly: %v", elapsed)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("SleepWithContext took too long: %v", elapsed)
	}
}

func TestSleepWithContext_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after 20ms
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	completed := SleepWithContext(ctx, 500*time.Millisecond)
	elapsed := time.Since(start)

	if completed {
		t.Error("SleepWithContext should return false when context is cancelled")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("SleepWithContext didn't cancel quickly enough: %v", elapsed)
	}
}

func TestSleepWithContext_AlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	start := time.Now()
	completed := SleepWithContext(ctx, 500*time.Millisecond)
	elapsed := time.Since(start)

	if completed {
		t.Error("SleepWithContext should return false when context is already cancelled")
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("SleepWithContext should return immediately for cancelled context: %v", elapsed)
	}
}

func TestSleepWithJitter(t *testing.T) {
	ctx := context.Background()
	base := 100 * time.Millisecond
	jitter := 0.2 // 20%

	minExpected := 80 * time.Millisecond  // base - 20%
	maxExpected := 120 * time.Millisecond // base + 20%

	// Run multiple times to test randomness
	for i := 0; i < 50; i++ {
		start := time.Now()
		completed := SleepWithJitter(ctx, base, jitter)
		elapsed := time.Since(start)

		if !completed {
			t.Error("SleepWithJitter should return true when sleep completes")
		}
		// Allow some tolerance for timing
		if elapsed < minExpected-10*time.Millisecond || elapsed > maxExpected+50*time.Millisecond {
			t.Errorf("SleepWithJitter duration %v out of expected range [%v, %v]",
				elapsed, minExpected, maxExpected)
		}
	}
}

func TestRandomWait(t *testing.T) {
	ctx := context.Background()
	minMs := 50
	maxMs := 100

	for i := 0; i < 20; i++ {
		start := time.Now()
		completed := RandomWait(ctx, minMs, maxMs)
		elapsed := time.Since(start)

		if !completed {
			t.Error("RandomWait should return true when wait completes")
		}
		if elapsed < time.Duration(minMs)*time.Millisecond {
			t.Errorf("RandomWait returned too quickly: %v", elapsed)
		}
		if elapsed > time.Duration(maxMs)*time.Millisecond+50*time.Millisecond {
			t.Errorf("RandomWait took too long: %v", elapsed)
		}
	}
}

func TestHumanDelay(t *testing.T) {
	tests := []struct {
		action string
		minMs  int
		maxMs  int
	}{
		{"click", 100, 300},
		{"scroll", 200, 500},
		{"navigate", 500, 1000},
		{"type", 50, 150},
		{"unknown", 100, 300}, // Falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				got := HumanDelay(tt.action)
				minExp := time.Duration(tt.minMs) * time.Millisecond
				maxExp := time.Duration(tt.maxMs) * time.Millisecond
				if got < minExp || got > maxExp {
					t.Errorf("HumanDelay(%q) = %v, want between %v and %v",
						tt.action, got, minExp, maxExp)
				}
			}
		})
	}
}

func TestDefaultTimingConfig(t *testing.T) {
	config := DefaultTimingConfig()

	if config.PollIntervalMinMs <= 0 {
		t.Error("PollIntervalMinMs should be positive")
	}
	if config.PollIntervalMaxMs < config.PollIntervalMinMs {
		t.Error("PollIntervalMaxMs should be >= PollIntervalMinMs")
	}
	if config.PreActionDelayMinMs <= 0 {
		t.Error("PreActionDelayMinMs should be positive")
	}
	if config.PreActionDelayMaxMs < config.PreActionDelayMinMs {
		t.Error("PreActionDelayMaxMs should be >= PreActionDelayMinMs")
	}
	if config.PostActionDelayMinMs <= 0 {
		t.Error("PostActionDelayMinMs should be positive")
	}
	if config.PostActionDelayMaxMs < config.PostActionDelayMinMs {
		t.Error("PostActionDelayMaxMs should be >= PostActionDelayMinMs")
	}
	if config.TypingDelayMinMs <= 0 {
		t.Error("TypingDelayMinMs should be positive")
	}
	if config.TypingDelayMaxMs < config.TypingDelayMinMs {
		t.Error("TypingDelayMaxMs should be >= TypingDelayMinMs")
	}
}

func TestTimingMethods(t *testing.T) {
	timing := NewTiming()

	t.Run("RandomPollInterval", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			interval := timing.RandomPollInterval()
			if interval < 800*time.Millisecond || interval > 1500*time.Millisecond {
				t.Errorf("RandomPollInterval() = %v, out of range", interval)
			}
		}
	})

	t.Run("PreActionDelay", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			delay := timing.PreActionDelay()
			if delay < 100*time.Millisecond || delay > 400*time.Millisecond {
				t.Errorf("PreActionDelay() = %v, out of range", delay)
			}
		}
	})

	t.Run("PostActionDelay", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			delay := timing.PostActionDelay()
			if delay < 150*time.Millisecond || delay > 500*time.Millisecond {
				t.Errorf("PostActionDelay() = %v, out of range", delay)
			}
		}
	})

	t.Run("TypingDelay", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			delay := timing.TypingDelay()
			if delay < 50*time.Millisecond || delay > 150*time.Millisecond {
				t.Errorf("TypingDelay() = %v, out of range", delay)
			}
		}
	})
}

package humanize

import (
	"testing"
)

func TestDefaultScrollConfig(t *testing.T) {
	config := DefaultScrollConfig()

	if config.MinScrollSteps <= 0 {
		t.Error("MinScrollSteps should be positive")
	}
	if config.MaxScrollSteps < config.MinScrollSteps {
		t.Error("MaxScrollSteps should be >= MinScrollSteps")
	}
	if config.MinStepDelayMs <= 0 {
		t.Error("MinStepDelayMs should be positive")
	}
	if config.MaxStepDelayMs < config.MinStepDelayMs {
		t.Error("MaxStepDelayMs should be >= MinStepDelayMs")
	}
	if config.ScrollMargin < 0 {
		t.Error("ScrollMargin should be non-negative")
	}
	if config.PreScrollDelayMinMs <= 0 {
		t.Error("PreScrollDelayMinMs should be positive")
	}
	if config.PreScrollDelayMaxMs < config.PreScrollDelayMinMs {
		t.Error("PreScrollDelayMaxMs should be >= PreScrollDelayMinMs")
	}
	if config.PostScrollDelayMinMs <= 0 {
		t.Error("PostScrollDelayMinMs should be positive")
	}
	if config.PostScrollDelayMaxMs < config.PostScrollDelayMinMs {
		t.Error("PostScrollDelayMaxMs should be >= PostScrollDelayMinMs")
	}
}

func TestEaseOutCubic(t *testing.T) {
	tests := []struct {
		name string
		t    float64
		want float64
	}{
		{"start", 0.0, 0.0},
		{"end", 1.0, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := easeOutCubic(tt.t)
			if !floatsClose(got, tt.want, 0.001) {
				t.Errorf("easeOutCubic(%v) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}

	// Test that easeOutCubic is faster at the start (deceleration)
	// At t=0.5, easeOutCubic should be > 0.5 (already past halfway)
	midpoint := easeOutCubic(0.5)
	if midpoint <= 0.5 {
		t.Errorf("easeOutCubic(0.5) = %v, expected > 0.5 for deceleration effect", midpoint)
	}

	// Test monotonicity
	prev := 0.0
	for i := 0; i <= 100; i++ {
		tVal := float64(i) / 100.0
		result := easeOutCubic(tVal)
		if result < prev {
			t.Errorf("easeOutCubic is not monotonic: f(%v) = %v < %v", tVal, result, prev)
		}
		prev = result
	}
}

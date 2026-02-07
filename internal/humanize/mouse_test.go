package humanize

import (
	"testing"
)

func TestGenerateBezierPath(t *testing.T) {
	tests := []struct {
		name      string
		start     Point
		end       Point
		numPoints int
	}{
		{
			name:      "horizontal line",
			start:     Point{X: 0, Y: 0},
			end:       Point{X: 100, Y: 0},
			numPoints: 10,
		},
		{
			name:      "vertical line",
			start:     Point{X: 0, Y: 0},
			end:       Point{X: 0, Y: 100},
			numPoints: 10,
		},
		{
			name:      "diagonal line",
			start:     Point{X: 0, Y: 0},
			end:       Point{X: 100, Y: 100},
			numPoints: 20,
		},
		{
			name:      "same point",
			start:     Point{X: 50, Y: 50},
			end:       Point{X: 50, Y: 50},
			numPoints: 5,
		},
		{
			name:      "minimum points",
			start:     Point{X: 0, Y: 0},
			end:       Point{X: 100, Y: 100},
			numPoints: 2,
		},
		{
			name:      "many points",
			start:     Point{X: 0, Y: 0},
			end:       Point{X: 500, Y: 500},
			numPoints: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := generateBezierPath(tt.start, tt.end, tt.numPoints)

			// Verify path length
			if len(path) != tt.numPoints {
				t.Errorf("generateBezierPath() returned %d points, want %d", len(path), tt.numPoints)
			}

			// Verify start point is close to expected
			if len(path) > 0 {
				first := path[0]
				if !pointsClose(first, tt.start, 0.01) {
					t.Errorf("First point %v not close to start %v", first, tt.start)
				}
			}

			// Verify end point is close to expected
			if len(path) > 0 {
				last := path[len(path)-1]
				if !pointsClose(last, tt.end, 0.01) {
					t.Errorf("Last point %v not close to end %v", last, tt.end)
				}
			}
		})
	}
}

func TestGenerateBezierPathMinPoints(t *testing.T) {
	// Test that minimum points is enforced
	path := generateBezierPath(Point{0, 0}, Point{100, 100}, 1)
	if len(path) < 2 {
		t.Errorf("generateBezierPath() should return at least 2 points, got %d", len(path))
	}

	path = generateBezierPath(Point{0, 0}, Point{100, 100}, 0)
	if len(path) < 2 {
		t.Errorf("generateBezierPath() should return at least 2 points, got %d", len(path))
	}
}

func TestEaseInOutCubic(t *testing.T) {
	tests := []struct {
		name string
		t    float64
		want float64
	}{
		{"start", 0.0, 0.0},
		{"end", 1.0, 1.0},
		{"middle", 0.5, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := easeInOutCubic(tt.t)
			if !floatsClose(got, tt.want, 0.001) {
				t.Errorf("easeInOutCubic(%v) = %v, want %v", tt.t, got, tt.want)
			}
		})
	}

	// Test monotonicity (output should always increase as input increases)
	prev := 0.0
	for i := 0; i <= 100; i++ {
		tVal := float64(i) / 100.0
		result := easeInOutCubic(tVal)
		if result < prev {
			t.Errorf("easeInOutCubic is not monotonic: f(%v) = %v < %v", tVal, result, prev)
		}
		prev = result
	}
}

func TestDefaultMouseConfig(t *testing.T) {
	config := DefaultMouseConfig()

	if config.MinSteps <= 0 {
		t.Error("MinSteps should be positive")
	}
	if config.MaxSteps < config.MinSteps {
		t.Error("MaxSteps should be >= MinSteps")
	}
	if config.MinStepDelayMs <= 0 {
		t.Error("MinStepDelayMs should be positive")
	}
	if config.MaxStepDelayMs < config.MinStepDelayMs {
		t.Error("MaxStepDelayMs should be >= MinStepDelayMs")
	}
	if config.ClickOffsetRadius < 0 {
		t.Error("ClickOffsetRadius should be non-negative")
	}
	if config.PreClickHoverMinMs <= 0 {
		t.Error("PreClickHoverMinMs should be positive")
	}
	if config.PreClickHoverMaxMs < config.PreClickHoverMinMs {
		t.Error("PreClickHoverMaxMs should be >= PreClickHoverMinMs")
	}
	if config.PostClickDwellMinMs <= 0 {
		t.Error("PostClickDwellMinMs should be positive")
	}
	if config.PostClickDwellMaxMs < config.PostClickDwellMinMs {
		t.Error("PostClickDwellMaxMs should be >= PostClickDwellMinMs")
	}
}

// Helper functions
func pointsClose(a, b Point, tolerance float64) bool {
	return floatsClose(a.X, b.X, tolerance) && floatsClose(a.Y, b.Y, tolerance)
}

func floatsClose(a, b, tolerance float64) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return diff <= tolerance
}

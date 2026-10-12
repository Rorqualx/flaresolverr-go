package dashboard

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// TestDashboardLoggingRedirect verifies that while the TUI owns the terminal
// the global log level is untouched, the log file keeps receiving lines, the
// console receives none, and everything is restored afterwards.
func TestDashboardLoggingRedirect(t *testing.T) {
	tests := []struct {
		name        string
		withFileLog bool
	}{
		{name: "with LOG_FILE", withFileLog: true},
		{name: "without LOG_FILE", withFileLog: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origLogger, origLevel := log.Logger, zerolog.GlobalLevel()
			t.Cleanup(func() {
				log.Logger = origLogger
				zerolog.SetGlobalLevel(origLevel)
			})

			var console, file bytes.Buffer
			log.Logger = zerolog.New(&console)
			zerolog.SetGlobalLevel(zerolog.DebugLevel)

			d := &Dashboard{done: make(chan struct{})}
			if tt.withFileLog {
				d.SetFileLog(&file)
			}

			d.redirectLogging()
			if got := zerolog.GlobalLevel(); got != zerolog.DebugLevel {
				t.Errorf("global level = %v while the TUI is up, want it left at debug", got)
			}
			log.Debug().Msg("during-tui")

			if strings.Contains(console.String(), "during-tui") {
				t.Error("log line reached the console while the TUI owned the terminal")
			}
			if tt.withFileLog && !strings.Contains(file.String(), "during-tui") {
				t.Error("log line did not reach the log file while the TUI was up")
			}

			d.restoreLogging()
			d.restoreLogging() // must be safe to call twice
			log.Info().Msg("after-tui")

			if !strings.Contains(console.String(), "after-tui") {
				t.Error("console logging was not restored after the TUI exited")
			}
			if got := zerolog.GlobalLevel(); got != zerolog.DebugLevel {
				t.Errorf("global level = %v after restore, want debug", got)
			}
		})
	}
}

// TestModelView_NarrowTerminal verifies no terminal size makes View panic.
// Widths under 8 used to reach strings.Repeat with a negative count.
func TestModelView_NarrowTerminal(t *testing.T) {
	for width := 0; width <= 60; width++ {
		for _, height := range []int{0, 1, 3, 8, 24} {
			m := Model{width: width, height: height}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("View() panicked at %dx%d: %v", width, height, r)
					}
				}()
				_ = m.View()
			}()
		}
	}
}

func TestRuleWidth(t *testing.T) {
	tests := []struct{ pane, want int }{
		{-5, 0}, {0, 0}, {1, 0}, {2, 0}, {3, 1}, {40, 38},
	}
	for _, tt := range tests {
		if got := ruleWidth(tt.pane); got != tt.want {
			t.Errorf("ruleWidth(%d) = %d, want %d", tt.pane, got, tt.want)
		}
	}
}

package dashboard

import (
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
)

// IsTTY returns true if stdout is an interactive terminal.
func IsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Dashboard manages the TUI lifecycle.
type Dashboard struct {
	program  *tea.Program
	events   *EventBuffer
	stopOnce sync.Once
	wg       sync.WaitGroup
	origLog  zerolog.Logger
}

// New creates a Dashboard wired to the application's live data sources.
func New(
	pool *browser.Pool,
	sessions *session.Manager,
	domainMgr *stats.Manager,
	startTime time.Time,
) *Dashboard {
	events := NewEventBuffer()
	collector := NewCollector(pool, sessions, domainMgr, events, startTime)
	model := NewModel(collector)
	program := tea.NewProgram(model, tea.WithAltScreen())

	return &Dashboard{
		program: program,
		events:  events,
	}
}

// Events returns the event buffer for use by the recording middleware.
func (d *Dashboard) Events() *EventBuffer {
	return d.events
}

// Start begins the TUI in a tracked goroutine.
// Logging is suppressed while the dashboard is active.
func (d *Dashboard) Start() {
	// Save current logger and suppress logging to prevent TUI corruption
	d.origLog = log.Logger
	log.Logger = log.Output(io.Discard)
	zerolog.SetGlobalLevel(zerolog.Disabled)

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if _, err := d.program.Run(); err != nil {
			// Restore logging before reporting error
			d.restoreLogging()
			log.Error().Err(err).Msg("Dashboard exited with error")
		}
	}()
}

// Stop gracefully shuts down the dashboard.
func (d *Dashboard) Stop() {
	d.stopOnce.Do(func() {
		d.program.Quit()

		// Wait with timeout
		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}

		d.restoreLogging()
	})
}

func (d *Dashboard) restoreLogging() {
	log.Logger = d.origLog
	if log.Logger.GetLevel() == zerolog.Disabled {
		// Fallback: restore a reasonable default
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		})
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// recordingWriter wraps http.ResponseWriter to capture the status code.
type recordingWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *recordingWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher for streaming responses.
func (rw *recordingWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// RecordRequests returns HTTP middleware that records each request
// into the dashboard's event buffer.
func RecordRequests(buf *EventBuffer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := &recordingWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			buf.Record(RequestEvent{
				Timestamp:  start,
				Method:     r.Method,
				Path:       r.URL.Path,
				StatusCode: wrapped.statusCode,
				Latency:    time.Since(start),
			})
		})
	}
}

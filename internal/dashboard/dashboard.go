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

	// Logging while the TUI owns the terminal
	origLog     zerolog.Logger
	fileLog     io.Writer // receives logs while the TUI is up; nil means none
	restoreOnce sync.Once

	// done is closed when the TUI has exited, for any reason
	done chan struct{}
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
		done:    make(chan struct{}),
	}
}

// SetFileLog sets the writer that keeps receiving log output while the TUI is
// running (normally the LOG_FILE handle). Call it before Start. Without it,
// logs are discarded while the TUI is up, since writing them to the terminal
// would corrupt the display.
func (d *Dashboard) SetFileLog(w io.Writer) {
	d.fileLog = w
}

// Done returns a channel that is closed when the TUI has exited, whether the
// user quit it, it failed, or Stop was called.
func (d *Dashboard) Done() <-chan struct{} {
	return d.done
}

// Events returns the event buffer for use by the recording middleware.
func (d *Dashboard) Events() *EventBuffer {
	return d.events
}

// Start begins the TUI in a tracked goroutine.
// Console logging is redirected while the dashboard is active; see SetFileLog.
func (d *Dashboard) Start() {
	d.redirectLogging()

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer close(d.done)

		_, err := d.program.Run()
		// The terminal is ours again: restore console logging before anything
		// else is logged, including the shutdown this exit triggers.
		d.restoreLogging()
		if err != nil {
			log.Error().Err(err).Msg("Dashboard exited with error")
		}
	}()
}

// redirectLogging keeps log output off the terminal while the TUI draws on it.
// Only the destination changes: the global log level is left alone, so file
// logging and the level the operator configured both keep working.
func (d *Dashboard) redirectLogging() {
	d.origLog = log.Logger
	if d.fileLog != nil {
		log.Logger = log.Output(d.fileLog)
		return
	}
	log.Logger = log.Output(io.Discard)
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

// restoreLogging puts back the logger that was active before Start. It runs
// once, from whichever of the TUI goroutine and Stop gets there first.
func (d *Dashboard) restoreLogging() {
	d.restoreOnce.Do(func() {
		log.Logger = d.origLog
	})
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

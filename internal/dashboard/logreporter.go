package dashboard

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
)

const (
	defaultReportInterval = 30 * time.Second
	logReporterMaxRows    = 5
)

// LogReporter periodically logs server stats when a TTY is not available.
// It provides the same insights as the TUI dashboard but via structured log output.
type LogReporter struct {
	collector *Collector
	events    *EventBuffer
	interval  time.Duration
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewLogReporter creates a log-based stats reporter using the same data sources as the TUI dashboard.
func NewLogReporter(
	pool *browser.Pool,
	sessions *session.Manager,
	domainMgr *stats.Manager,
	startTime time.Time,
	interval time.Duration,
) *LogReporter {
	if interval <= 0 {
		interval = defaultReportInterval
	}
	events := NewEventBuffer()
	collector := NewCollector(pool, sessions, domainMgr, events, startTime)
	return &LogReporter{
		collector: collector,
		events:    events,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}
}

// Events returns the event buffer for use by the recording middleware.
func (r *LogReporter) Events() *EventBuffer {
	return r.events
}

// Start begins periodic stats reporting.
func (r *LogReporter) Start() {
	r.wg.Add(1)
	go r.reportLoop()
	log.Info().
		Dur("interval", r.interval).
		Msg("Log-based stats reporter started")
}

// Stop shuts down the reporter.
func (r *LogReporter) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

func (r *LogReporter) reportLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.report()
		case <-r.stopCh:
			return
		}
	}
}

func (r *LogReporter) report() {
	snap := r.collector.Collect(logReporterMaxRows)

	// Server stats
	log.Info().
		Str("uptime", formatDuration(snap.Uptime)).
		Int64("total_requests", snap.TotalRequests).
		Str("req_per_sec", fmt.Sprintf("%.1f", snap.RequestsPerSec)).
		Int("goroutines", snap.Goroutines).
		Str("heap_mb", fmt.Sprintf("%.1f", snap.HeapAllocMB)).
		Int("pool_available", snap.PoolAvailable).
		Int("pool_size", snap.PoolSize).
		Int("sessions", snap.SessionCount).
		Int("domains", snap.DomainCount).
		Msg("Server stats")

	// Top domains (if any)
	for _, d := range snap.TopDomains {
		log.Info().
			Str("domain", d.Domain).
			Int64("requests", d.RequestCount).
			Str("success_rate", fmt.Sprintf("%.0f%%", d.SuccessRate)).
			Int64("avg_latency_ms", d.AvgLatencyMs).
			Msg("Domain stats")
	}
}

// formatDuration is defined in model.go and shared across the package.

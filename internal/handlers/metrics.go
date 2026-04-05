package handlers

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// handleMetrics serves Prometheus-compatible metrics at /metrics.
// Uses the same data sources as the dashboard and /health endpoint.
// No external Prometheus client library needed — just text format output.
func (h *Handler) handleMetrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder

	// Pool metrics
	poolStats := h.pool.Stats()
	writeGauge(&b, "flaresolverr_pool_size", "Configured browser pool size", float64(h.pool.Size()))
	writeGauge(&b, "flaresolverr_pool_available", "Currently available browsers", float64(h.pool.Available()))
	writeCounter(&b, "flaresolverr_pool_acquired_total", "Total browsers acquired from pool", float64(poolStats.Acquired))
	writeCounter(&b, "flaresolverr_pool_released_total", "Total browsers released to pool", float64(poolStats.Released))
	writeCounter(&b, "flaresolverr_pool_recycled_total", "Total browsers recycled", float64(poolStats.Recycled))
	writeCounter(&b, "flaresolverr_pool_errors_total", "Total pool errors", float64(poolStats.Errors))

	// Session metrics
	if h.sessions != nil {
		writeGauge(&b, "flaresolverr_sessions_active", "Active browser sessions", float64(h.sessions.Count()))
	}

	// Go runtime metrics
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	writeGauge(&b, "flaresolverr_goroutines", "Number of goroutines", float64(runtime.NumGoroutine()))
	writeGauge(&b, "flaresolverr_heap_alloc_bytes", "Heap memory allocated in bytes", float64(mem.HeapAlloc))
	writeGauge(&b, "flaresolverr_heap_sys_bytes", "Heap memory obtained from OS", float64(mem.HeapSys))
	writeCounter(&b, "flaresolverr_gc_total", "Total garbage collections", float64(mem.NumGC))

	// Uptime
	writeGauge(&b, "flaresolverr_uptime_seconds", "Seconds since server start", time.Since(serverStartTime).Seconds())

	// Domain stats
	if h.domainStats != nil {
		allStats := h.domainStats.AllStats()
		for domain, ds := range allStats {
			labels := fmt.Sprintf(`domain="%s"`, escapeProm(domain))
			writeCounterLabeled(&b, "flaresolverr_domain_requests_total", "Total requests per domain", labels, float64(ds.RequestCount))
			writeCounterLabeled(&b, "flaresolverr_domain_successes_total", "Successful requests per domain", labels, float64(ds.SuccessCount))
			writeCounterLabeled(&b, "flaresolverr_domain_errors_total", "Failed requests per domain", labels, float64(ds.ErrorCount))
			writeCounterLabeled(&b, "flaresolverr_domain_rate_limits_total", "Rate-limited responses per domain", labels, float64(ds.RateLimitCount))
			writeGaugeLabeled(&b, "flaresolverr_domain_avg_latency_ms", "Average latency per domain", labels, float64(ds.AvgLatencyMs))
			writeGaugeLabeled(&b, "flaresolverr_domain_suggested_delay_ms", "Suggested delay per domain", labels, float64(ds.SuggestedDelayMs))
		}
	}

	w.Write([]byte(b.String()))
}

// startTime tracks when the server started for uptime calculation
var serverStartTime = time.Now()

func writeGauge(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, value)
}

func writeCounter(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %g\n", name, help, name, name, value)
}

func writeGaugeLabeled(b *strings.Builder, name, help, labels string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s{%s} %g\n", name, help, name, name, labels, value)
}

func writeCounterLabeled(b *strings.Builder, name, help, labels string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s{%s} %g\n", name, help, name, name, labels, value)
}

func escapeProm(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

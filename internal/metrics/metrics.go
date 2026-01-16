// Package metrics provides Prometheus metrics for monitoring FlareSolverr.
package metrics

import (
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// RequestsTotal counts total requests by command and status.
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flaresolverr_requests_total",
			Help: "Total number of requests processed",
		},
		[]string{"command", "status"},
	)

	// RequestDuration tracks request duration by command.
	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "flaresolverr_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12), // 0.1s to ~400s
		},
		[]string{"command"},
	)

	// BrowserPoolSize shows the configured pool size.
	BrowserPoolSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flaresolverr_browser_pool_size",
			Help: "Configured browser pool size",
		},
	)

	// BrowserPoolAvailable shows available browsers in the pool.
	BrowserPoolAvailable = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flaresolverr_browser_pool_available",
			Help: "Available browsers in pool",
		},
	)

	// BrowserPoolAcquired counts total browser acquisitions.
	BrowserPoolAcquired = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "flaresolverr_browser_pool_acquired_total",
			Help: "Total browser acquisitions from pool",
		},
	)

	// BrowserPoolRecycled counts browser recycles.
	BrowserPoolRecycled = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "flaresolverr_browser_pool_recycled_total",
			Help: "Total browsers recycled",
		},
	)

	// ActiveSessions shows current active sessions.
	ActiveSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flaresolverr_active_sessions",
			Help: "Number of active sessions",
		},
	)

	// ChallengesSolved counts solved challenges by type.
	ChallengesSolved = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flaresolverr_challenges_solved_total",
			Help: "Total challenges solved by type",
		},
		[]string{"type"},
	)

	// ChallengesFailed counts failed challenge attempts.
	ChallengesFailed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flaresolverr_challenges_failed_total",
			Help: "Total challenges failed by reason",
		},
		[]string{"reason"},
	)

	// MemoryUsageBytes shows current memory usage.
	MemoryUsageBytes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flaresolverr_memory_usage_bytes",
			Help: "Current memory usage in bytes (alloc)",
		},
	)

	// MemorySysBytes shows system memory obtained.
	MemorySysBytes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flaresolverr_memory_sys_bytes",
			Help: "Total memory obtained from system",
		},
	)

	// GoroutineCount shows current goroutine count.
	GoroutineCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "flaresolverr_goroutines",
			Help: "Current number of goroutines",
		},
	)

	// BuildInfo provides build information as labels.
	BuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "flaresolverr_build_info",
			Help: "Build information",
		},
		[]string{"version", "go_version"},
	)
)

func init() {
	// Register all metrics
	prometheus.MustRegister(
		RequestsTotal,
		RequestDuration,
		BrowserPoolSize,
		BrowserPoolAvailable,
		BrowserPoolAcquired,
		BrowserPoolRecycled,
		ActiveSessions,
		ChallengesSolved,
		ChallengesFailed,
		MemoryUsageBytes,
		MemorySysBytes,
		GoroutineCount,
		BuildInfo,
	)
}

// Handler returns the Prometheus HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// SetBuildInfo sets the build info metric.
func SetBuildInfo(version, goVersion string) {
	BuildInfo.WithLabelValues(version, goVersion).Set(1)
}

// StartMemoryCollector starts a goroutine that periodically updates memory metrics.
func StartMemoryCollector(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updateMemoryMetrics()
		case <-stopCh:
			return
		}
	}
}

// updateMemoryMetrics updates memory-related metrics.
func updateMemoryMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	MemoryUsageBytes.Set(float64(m.Alloc))
	MemorySysBytes.Set(float64(m.Sys))
	GoroutineCount.Set(float64(runtime.NumGoroutine()))
}

// RecordRequest records metrics for a completed request.
func RecordRequest(command, status string, duration time.Duration) {
	RequestsTotal.WithLabelValues(command, status).Inc()
	RequestDuration.WithLabelValues(command).Observe(duration.Seconds())
}

// RecordChallengeSolved records a solved challenge.
func RecordChallengeSolved(challengeType string) {
	ChallengesSolved.WithLabelValues(challengeType).Inc()
}

// RecordChallengeFailed records a failed challenge attempt.
func RecordChallengeFailed(reason string) {
	ChallengesFailed.WithLabelValues(reason).Inc()
}

// UpdatePoolMetrics updates browser pool metrics.
func UpdatePoolMetrics(size, available int, acquired, recycled int64) {
	BrowserPoolSize.Set(float64(size))
	BrowserPoolAvailable.Set(float64(available))
	// Note: counters are incremental, so we use direct counter methods in the code
}

// UpdateSessionMetrics updates session count metric.
func UpdateSessionMetrics(count int) {
	ActiveSessions.Set(float64(count))
}

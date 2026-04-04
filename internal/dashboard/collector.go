package dashboard

import (
	"runtime"
	"sort"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
)

// DomainSummary is a simplified view of per-domain stats for display.
type DomainSummary struct {
	Domain       string
	RequestCount int64
	SuccessRate  float64
	AvgLatencyMs int64
}

// Snapshot is the complete state for one dashboard render cycle.
type Snapshot struct {
	// Request log (newest first)
	RecentRequests []RequestEvent

	// Request rate
	TotalRequests  int64
	RequestsPerSec float64

	// Browser pool
	PoolSize      int
	PoolAvailable int
	PoolAcquired  int64
	PoolReleased  int64
	PoolRecycled  int64
	PoolErrors    int64

	// Sessions
	SessionCount int
	SessionIDs   []string

	// Domain stats (top N by request count)
	TopDomains  []DomainSummary
	DomainCount int

	// Runtime
	Goroutines  int
	HeapAllocMB float64

	// Server
	Uptime      time.Duration
	CollectedAt time.Time
}

// Collector gathers data from all sources to produce snapshots.
type Collector struct {
	pool      *browser.Pool
	sessions  *session.Manager
	domainMgr *stats.Manager
	events    *EventBuffer
	startTime time.Time

	// For rate calculation
	lastTotal int64
	lastTime  time.Time
}

// NewCollector creates a Collector wired to the application's live data sources.
func NewCollector(
	pool *browser.Pool,
	sessions *session.Manager,
	domainMgr *stats.Manager,
	events *EventBuffer,
	startTime time.Time,
) *Collector {
	return &Collector{
		pool:      pool,
		sessions:  sessions,
		domainMgr: domainMgr,
		events:    events,
		startTime: startTime,
		lastTime:  startTime,
	}
}

// Collect gathers a point-in-time snapshot from all data sources.
func (c *Collector) Collect(maxRequests int) Snapshot {
	now := time.Now()

	// Request events
	recent, total := c.events.Snapshot(maxRequests)

	// Calculate request rate with smoothing
	elapsed := now.Sub(c.lastTime).Seconds()
	var rps float64
	if elapsed > 0 {
		rps = float64(total-c.lastTotal) / elapsed
	}
	c.lastTotal = total
	c.lastTime = now

	// Pool stats
	poolStats := c.pool.Stats()

	// Domain stats — get all, sort by request count, take top 10
	var topDomains []DomainSummary
	var domainCount int
	if c.domainMgr != nil {
		allStats := c.domainMgr.AllStats()
		domainCount = len(allStats)
		for domain, ds := range allStats {
			var successRate float64
			if ds.RequestCount > 0 {
				successRate = float64(ds.SuccessCount) / float64(ds.RequestCount) * 100
			}
			topDomains = append(topDomains, DomainSummary{
				Domain:       domain,
				RequestCount: ds.RequestCount,
				SuccessRate:  successRate,
				AvgLatencyMs: ds.AvgLatencyMs,
			})
		}
		sort.Slice(topDomains, func(i, j int) bool {
			return topDomains[i].RequestCount > topDomains[j].RequestCount
		})
		if len(topDomains) > 10 {
			topDomains = topDomains[:10]
		}
	}

	// Runtime
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	return Snapshot{
		RecentRequests: recent,
		TotalRequests:  total,
		RequestsPerSec: rps,

		PoolSize:      c.pool.Size(),
		PoolAvailable: c.pool.Available(),
		PoolAcquired:  poolStats.Acquired,
		PoolReleased:  poolStats.Released,
		PoolRecycled:  poolStats.Recycled,
		PoolErrors:    poolStats.Errors,

		SessionCount: c.sessions.Count(),
		SessionIDs:   c.sessions.List(),

		TopDomains:  topDomains,
		DomainCount: domainCount,

		Goroutines:  runtime.NumGoroutine(),
		HeapAllocMB: float64(mem.HeapAlloc) / 1024 / 1024,

		Uptime:      now.Sub(c.startTime),
		CollectedAt: now,
	}
}

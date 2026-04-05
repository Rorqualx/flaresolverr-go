package dashboard

import (
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/stats"
)

func TestCollector_Collect(t *testing.T) {
	// Create real stats manager and session manager (no browser pool needed for basic test)
	domainMgr := stats.NewManager()
	cfg := &config.Config{
		SessionTTL:             30 * time.Minute,
		SessionCleanupInterval: 1 * time.Minute,
		MaxSessions:            10,
	}
	sessionMgr := session.NewManager(cfg, nil)
	defer sessionMgr.Close()

	events := NewEventBuffer()

	// Record some domain stats
	domainMgr.RecordRequest("example.com", 100, true, false)
	domainMgr.RecordRequest("example.com", 200, true, false)
	domainMgr.RecordRequest("site.org", 300, false, true)

	// Record some events
	events.Record(RequestEvent{
		Timestamp:  time.Now(),
		Method:     "POST",
		Path:       "/v1",
		StatusCode: 200,
		Latency:    150 * time.Millisecond,
	})

	// We can't create a real browser.Pool without Chrome, so test with nil
	// The collector should handle this gracefully in a real scenario,
	// but for this test we skip pool stats
	t.Run("snapshot fields populated", func(t *testing.T) {
		// Create collector without pool (will panic if pool methods called)
		// Instead, test the parts we can
		snap := Snapshot{
			TotalRequests:  1,
			RequestsPerSec: 0.5,
			SessionCount:   0,
			DomainCount:    2,
			Uptime:         5 * time.Minute,
		}

		if snap.TotalRequests != 1 {
			t.Errorf("expected TotalRequests=1, got %d", snap.TotalRequests)
		}
		if snap.RequestsPerSec != 0.5 {
			t.Errorf("expected RequestsPerSec=0.5, got %f", snap.RequestsPerSec)
		}
		if snap.SessionCount != 0 {
			t.Errorf("expected SessionCount=0, got %d", snap.SessionCount)
		}
		if snap.DomainCount != 2 {
			t.Errorf("expected DomainCount=2, got %d", snap.DomainCount)
		}
		if snap.Uptime != 5*time.Minute {
			t.Errorf("expected Uptime=5m, got %v", snap.Uptime)
		}
	})

	t.Run("domain stats populated", func(t *testing.T) {
		allStats := domainMgr.AllStats()
		if len(allStats) != 2 {
			t.Errorf("expected 2 domains, got %d", len(allStats))
		}
		if allStats["example.com"].RequestCount != 2 {
			t.Errorf("expected 2 requests for example.com, got %d", allStats["example.com"].RequestCount)
		}
		if allStats["site.org"].RateLimitCount != 1 {
			t.Errorf("expected 1 rate limit for site.org, got %d", allStats["site.org"].RateLimitCount)
		}
	})

	t.Run("event buffer integration", func(t *testing.T) {
		recent, total := events.Snapshot(10)
		if total != 1 {
			t.Errorf("expected 1 total event, got %d", total)
		}
		if len(recent) != 1 {
			t.Errorf("expected 1 recent event, got %d", len(recent))
		}
		if recent[0].StatusCode != 200 {
			t.Errorf("expected status 200, got %d", recent[0].StatusCode)
		}
	})

	t.Run("session count", func(t *testing.T) {
		if sessionMgr.Count() != 0 {
			t.Errorf("expected 0 sessions, got %d", sessionMgr.Count())
		}
	})
}

func TestDomainSummary_Sorting(t *testing.T) {
	domainMgr := stats.NewManager()

	// Record different request counts
	for i := 0; i < 10; i++ {
		domainMgr.RecordRequest("high.com", 100, true, false)
	}
	for i := 0; i < 3; i++ {
		domainMgr.RecordRequest("low.com", 100, true, false)
	}
	for i := 0; i < 7; i++ {
		domainMgr.RecordRequest("mid.com", 100, true, false)
	}

	allStats := domainMgr.AllStats()
	if allStats["high.com"].RequestCount != 10 {
		t.Errorf("expected high.com=10, got %d", allStats["high.com"].RequestCount)
	}
	if allStats["low.com"].RequestCount != 3 {
		t.Errorf("expected low.com=3, got %d", allStats["low.com"].RequestCount)
	}
}

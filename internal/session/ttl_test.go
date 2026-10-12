package session

import (
	"sync"
	"testing"
	"time"
)

// TestSessionTTL_ConcurrentReadWrite exercises SetTTL (keepalive) against
// EffectiveTTL and RemainingTTL (cleanup routine, dashboard). Run with -race:
// the read used to bypass the lock the write takes.
func TestSessionTTL_ConcurrentReadWrite(t *testing.T) {
	sess := &Session{ID: "ttl-race"}
	sess.Touch()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 1; i <= 2000; i++ {
			sess.SetTTL(time.Duration(i) * time.Second)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if got := sess.EffectiveTTL(time.Minute); got <= 0 {
				t.Errorf("EffectiveTTL = %v, want positive", got)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = sess.RemainingTTL(time.Minute)
		}
	}()
	wg.Wait()
}

func TestSessionEffectiveTTL_Fallback(t *testing.T) {
	tests := []struct {
		name       string
		sessionTTL time.Duration
		defaultTTL time.Duration
		want       time.Duration
	}{
		{name: "no per-session TTL uses default", sessionTTL: 0, defaultTTL: 30 * time.Minute, want: 30 * time.Minute},
		{name: "per-session TTL wins", sessionTTL: 5 * time.Minute, defaultTTL: 30 * time.Minute, want: 5 * time.Minute},
		{name: "negative per-session TTL uses default", sessionTTL: -time.Second, defaultTTL: time.Minute, want: time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &Session{}
			sess.SetTTL(tt.sessionTTL)
			if got := sess.EffectiveTTL(tt.defaultTTL); got != tt.want {
				t.Errorf("EffectiveTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

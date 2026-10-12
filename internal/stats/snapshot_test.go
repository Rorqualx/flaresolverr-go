package stats

import (
	"encoding/json"
	"sync"
	"testing"
)

// TestToJSON_ReturnsCopies verifies a stats snapshot shares no maps, slices or
// pointers with the live counters: changing the snapshot must not change the
// stats, and vice versa.
func TestToJSON_ReturnsCopies(t *testing.T) {
	m := NewManager()
	defer m.Close()

	const domain = "example.com"
	attempts, timeout := 2, 5000
	m.RecordSolveOutcome(domain, "2captcha", true, 1200)
	m.SetDomainSolverPrefs(domain, &SolverPreferences{
		NativeAttempts:    &attempts,
		TimeoutOverrideMs: &timeout,
		DisableMethods:    []string{"keyboard"},
	})

	snapshot := m.AllStats()[domain]
	if snapshot.SolveStats == nil || snapshot.SolverPrefs == nil {
		t.Fatalf("snapshot is missing solve stats or prefs: %+v", snapshot)
	}

	// Scribble over everything reachable from the snapshot
	snapshot.SolveStats.ExternalAttempts["2captcha"] = 999
	snapshot.SolveStats.ExternalSuccesses["injected"] = 1
	snapshot.SolverPrefs.DisableMethods[0] = "tampered"
	*snapshot.SolverPrefs.NativeAttempts = 99
	*snapshot.SolverPrefs.TimeoutOverrideMs = 1

	fresh := m.AllStats()[domain]
	if got := fresh.SolveStats.ExternalAttempts["2captcha"]; got != 1 {
		t.Errorf("live ExternalAttempts[2captcha] = %d after editing a snapshot, want 1", got)
	}
	if _, leaked := fresh.SolveStats.ExternalSuccesses["injected"]; leaked {
		t.Error("a key added to a snapshot map appeared in the live stats")
	}
	if got := fresh.SolverPrefs.DisableMethods[0]; got != "keyboard" {
		t.Errorf("live DisableMethods[0] = %q after editing a snapshot, want keyboard", got)
	}
	if got := *fresh.SolverPrefs.NativeAttempts; got != 2 {
		t.Errorf("live NativeAttempts = %d after editing a snapshot, want 2", got)
	}
	if got := *fresh.SolverPrefs.TimeoutOverrideMs; got != 5000 {
		t.Errorf("live TimeoutOverrideMs = %d after editing a snapshot, want 5000", got)
	}
}

// TestToJSON_ConcurrentWithWrites serializes snapshots while the counters are
// being written. With shared maps this is a concurrent map read and write,
// which crashes the process; run with -race.
func TestToJSON_ConcurrentWithWrites(t *testing.T) {
	m := NewManager()
	defer m.Close()

	const domain = "example.com"
	m.RecordSolveOutcome(domain, "2captcha", true, 100)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			m.RecordSolveOutcome(domain, "capsolver", i%2 == 0, 100)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if _, err := json.Marshal(m.AllStats()); err != nil {
				t.Errorf("marshal snapshot: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

func TestSolverPreferencesClone_Nil(t *testing.T) {
	var prefs *SolverPreferences
	if prefs.clone() != nil {
		t.Error("clone of nil preferences is not nil")
	}
	if cloneCounts(nil) != nil {
		t.Error("cloneCounts(nil) is not nil")
	}
}

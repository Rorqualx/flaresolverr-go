package captcha

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/go-rod/rod/lib/proto"
)

func TestParseChallengeParams(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantOK  bool
		wantKey string
		wantCD  string
		wantPD  string
		wantAct string
	}{
		{
			name:    "full managed-challenge params",
			json:    `{"sitekey":"0x4AAAAAAADnPIDROrmt1Wwj","action":"managed","cData":"CDATA","chlPageData":"PAGEDATA"}`,
			wantOK:  true,
			wantKey: "0x4AAAAAAADnPIDROrmt1Wwj",
			wantCD:  "CDATA",
			wantPD:  "PAGEDATA",
			wantAct: "managed",
		},
		{
			name:    "sitekey only (explicit widget)",
			json:    `{"sitekey":"0xABC","action":"","cData":"","chlPageData":""}`,
			wantOK:  true,
			wantKey: "0xABC",
		},
		{name: "empty sitekey rejected", json: `{"sitekey":"","cData":"x"}`, wantOK: false},
		{name: "null rejected", json: `null`, wantOK: false},
		{name: "malformed rejected", json: `{not json`, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseChallengeParams([]byte(tt.json))
			if ok != tt.wantOK {
				t.Fatalf("parseChallengeParams ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if p.SiteKey != tt.wantKey || p.CData != tt.wantCD || p.PageData != tt.wantPD || p.Action != tt.wantAct {
				t.Errorf("got %+v, want sitekey=%q cData=%q chlPageData=%q action=%q",
					p, tt.wantKey, tt.wantCD, tt.wantPD, tt.wantAct)
			}
		})
	}
}

func TestEvalResultString(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "json string value", raw: `{"result":{"value":"{\"sitekey\":\"0xABC\"}"}}`, want: `{"sitekey":"0xABC"}`, ok: true},
		{name: "null string", raw: `{"result":{"value":"null"}}`, ok: false},
		{name: "empty string", raw: `{"result":{"value":""}}`, ok: false},
		{name: "non-string value", raw: `{"result":{"value":123}}`, ok: false},
		{name: "malformed", raw: `not json`, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := evalResultString([]byte(tt.raw))
			if ok != tt.ok || got != tt.want {
				t.Errorf("evalResultString = (%q,%v), want (%q,%v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestEvalResultBool(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want bool
	}{
		{`{"result":{"value":true}}`, true},
		{`{"result":{"value":false}}`, false},
		{`{"result":{}}`, false},
		{`garbage`, false},
	} {
		if got := evalResultBool([]byte(tt.raw)); got != tt.want {
			t.Errorf("evalResultBool(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestOOPIFStateBelongs(t *testing.T) {
	st := &oopifState{
		pageSession: proto.TargetSessionID("PAGE"),
		children:    []proto.TargetSessionID{"CHILD1"},
	}
	tests := []struct {
		name     string
		envelope proto.TargetSessionID
		want     bool
	}{
		{"page session", "PAGE", true},
		{"known child (nested)", "CHILD1", true},
		{"unrelated session", "OTHER", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := st.belongs(tt.envelope); got != tt.want {
				t.Errorf("belongs(%q) = %v, want %v", tt.envelope, got, tt.want)
			}
		})
	}
}

// TestOOPIFStateParamsNilSafe ensures the accessors are safe on a zero/!installed state.
func TestOOPIFStateParamsNilSafe(t *testing.T) {
	ctx := context.Background()

	var st *oopifState
	if _, ok := st.params(ctx); ok {
		t.Error("nil state params() should be (nil,false)")
	}
	if st.injectCallback(ctx, "x") {
		t.Error("nil state injectCallback() should be false")
	}
	st.stop() // must not panic

	empty := &oopifState{} // installed but no browser/children
	if _, ok := empty.params(ctx); ok {
		t.Error("empty state params() should be (nil,false)")
	}
	empty.stop() // no listener was started: must not panic or block
}

// TestOOPIFStateUntrack: a detached child is forgotten, so later lookups do not
// send commands to a dead session and the list cannot grow without bound.
func TestOOPIFStateUntrack(t *testing.T) {
	tests := []struct {
		name    string
		start   []proto.TargetSessionID
		detach  proto.TargetSessionID
		want    []proto.TargetSessionID
		belongs map[proto.TargetSessionID]bool
	}{
		{
			name:    "middle child",
			start:   []proto.TargetSessionID{"A", "B", "C"},
			detach:  "B",
			want:    []proto.TargetSessionID{"A", "C"},
			belongs: map[proto.TargetSessionID]bool{"A": true, "B": false, "C": true},
		},
		{
			name:   "only child",
			start:  []proto.TargetSessionID{"A"},
			detach: "A",
			want:   []proto.TargetSessionID{},
		},
		{
			name:   "unknown session is ignored",
			start:  []proto.TargetSessionID{"A", "B"},
			detach: "Z",
			want:   []proto.TargetSessionID{"A", "B"},
		},
		{
			name:   "the page's own session is never a child",
			start:  []proto.TargetSessionID{"A"},
			detach: "PAGE",
			want:   []proto.TargetSessionID{"A"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &oopifState{pageSession: "PAGE"}
			for _, child := range tt.start {
				if !st.track(child) {
					t.Fatalf("track(%q) = false", child)
				}
			}
			st.untrack(tt.detach)

			got := st.snapshot()
			if len(got) != len(tt.want) {
				t.Fatalf("children = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("children = %v, want %v", got, tt.want)
				}
			}
			for session, want := range tt.belongs {
				if st.belongs(session) != want {
					t.Errorf("belongs(%q) = %v, want %v", session, !want, want)
				}
			}
			if !st.belongs("PAGE") {
				t.Error("the page session must always belong")
			}
		})
	}
}

// TestOOPIFStateTrackIsCapped: an ad-heavy page cannot grow the list forever,
// and detaching makes room again.
func TestOOPIFStateTrackIsCapped(t *testing.T) {
	st := &oopifState{pageSession: "PAGE"}
	for i := 0; i < maxOOPIFChildren; i++ {
		if !st.track(proto.TargetSessionID(fmt.Sprintf("child-%d", i))) {
			t.Fatalf("track #%d refused below the cap", i)
		}
	}
	if st.track("one-too-many") {
		t.Error("track accepted a child beyond the cap")
	}
	if got := len(st.snapshot()); got != maxOOPIFChildren {
		t.Errorf("children = %d, want %d", got, maxOOPIFChildren)
	}
	if st.belongs("one-too-many") {
		t.Error("a refused child must not be remembered")
	}

	st.untrack("child-0")
	if !st.track("replacement") {
		t.Error("track refused although a child had detached")
	}
}

// TestOOPIFStateSnapshotIsACopy: callers iterate the snapshot without the lock.
func TestOOPIFStateSnapshotIsACopy(t *testing.T) {
	st := &oopifState{pageSession: "PAGE"}
	st.track("A")
	snap := st.snapshot()
	snap[0] = "MUTATED"
	if !st.belongs("A") || st.belongs("MUTATED") {
		t.Error("mutating a snapshot changed the tracked children")
	}
}

// TestOOPIFStateConcurrentTracking exercises attach/detach/lookup from several
// goroutines; run with -race.
func TestOOPIFStateConcurrentTracking(t *testing.T) {
	st := &oopifState{pageSession: "PAGE"}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				child := proto.TargetSessionID(fmt.Sprintf("w%d-%d", worker, i))
				st.track(child)
				st.belongs(child)
				st.snapshot()
				st.untrack(child)
			}
		}(worker)
	}
	wg.Wait()
	if got := len(st.snapshot()); got != 0 {
		t.Errorf("children left = %d, want 0", got)
	}
}

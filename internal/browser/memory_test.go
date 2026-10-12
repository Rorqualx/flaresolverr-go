package browser

import (
	"testing"
	"time"

	"github.com/go-rod/rod"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

func TestParseCgroupWorkingSet(t *testing.T) {
	const v2Stat = "anon 524288000\nfile 314572800\ninactive_file 209715200\nactive_file 104857600\n"

	tests := []struct {
		name        string
		usage       string
		stat        string
		inactiveKey string
		want        uint64
		wantErr     bool
	}{
		{name: "v2 subtracts inactive file cache", usage: "838860800\n", stat: v2Stat, inactiveKey: "inactive_file", want: 838860800 - 209715200},
		{name: "v1 key", usage: "1000", stat: "total_inactive_file 400\ninactive_file 999\n", inactiveKey: "total_inactive_file", want: 600},
		{name: "v1 key must match exactly", usage: "1000", stat: "total_inactive_file 400\n", inactiveKey: "inactive_file", want: 1000},
		{name: "no stat file", usage: "1000", stat: "", inactiveKey: "inactive_file", want: 1000},
		{name: "inactive larger than usage clamps to zero", usage: "100", stat: "inactive_file 500\n", inactiveKey: "inactive_file", want: 0},
		{name: "unparseable inactive falls back to usage", usage: "1000", stat: "inactive_file lots\n", inactiveKey: "inactive_file", want: 1000},
		{name: "cgroup v2 max sentinel is not a number", usage: "max\n", inactiveKey: "inactive_file", wantErr: true},
		{name: "empty usage", usage: "", inactiveKey: "inactive_file", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCgroupWorkingSet([]byte(tt.usage), []byte(tt.stat), tt.inactiveKey)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseCgroupWorkingSet() = %d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCgroupWorkingSet() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("parseCgroupWorkingSet() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseProcStat(t *testing.T) {
	// Field 24 (rss) is 12345 in each well-formed line below
	const tail = " S 77 42 42 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 12 0 1000 99999999 12345 18446744073709551615 0 0"

	tests := []struct {
		name    string
		line    string
		want    procStat
		wantErr bool
	}{
		{name: "plain command", line: "42 (chromium)" + tail, want: procStat{pid: 42, ppid: 77, rssPages: 12345}},
		{name: "command with spaces", line: "42 (Web Content)" + tail, want: procStat{pid: 42, ppid: 77, rssPages: 12345}},
		{name: "command with parentheses", line: "42 (a) b (c))" + tail, want: procStat{pid: 42, ppid: 77, rssPages: 12345}},
		{name: "too few fields", line: "42 (chromium) S 77 42", wantErr: true},
		{name: "no command", line: "42 chromium S 77", wantErr: true},
		{name: "empty", line: "", wantErr: true},
		{name: "non-numeric pid", line: "x (chromium)" + tail, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProcStat([]byte(tt.line))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseProcStat() = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProcStat() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("parseProcStat() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSumProcessTreeRSS(t *testing.T) {
	procs := []procStat{
		{pid: 1, ppid: 0, rssPages: 1},      // init
		{pid: 7, ppid: 1, rssPages: 10},     // this service
		{pid: 20, ppid: 7, rssPages: 100},   // chrome
		{pid: 21, ppid: 20, rssPages: 1000}, // renderer
		{pid: 22, ppid: 20, rssPages: 2000}, // gpu
		{pid: 30, ppid: 7, rssPages: 300},   // second chrome
		{pid: 99, ppid: 1, rssPages: 50000}, // unrelated process
	}

	tests := []struct {
		name string
		root int
		want uint64
	}{
		{name: "service and all descendants", root: 7, want: 10 + 100 + 1000 + 2000 + 300},
		{name: "one browser subtree", root: 20, want: 100 + 1000 + 2000},
		{name: "leaf", root: 30, want: 300},
		{name: "unknown root", root: 12345, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sumProcessTreeRSS(procs, tt.root); got != tt.want {
				t.Errorf("sumProcessTreeRSS(root=%d) = %d, want %d", tt.root, got, tt.want)
			}
		})
	}

	t.Run("cycle in a torn /proc snapshot terminates", func(t *testing.T) {
		cyclic := []procStat{{pid: 5, ppid: 6, rssPages: 1}, {pid: 6, ppid: 5, rssPages: 2}}
		if got := sumProcessTreeRSS(cyclic, 5); got != 3 {
			t.Errorf("sumProcessTreeRSS on a cycle = %d, want 3", got)
		}
	})
}

// TestCheckMemory drives the monitor step with a fake reader: it must recycle
// when over the limit, then hold off for the cooldown even though usage stays
// high (open sessions keep it there), so it cannot storm.
func TestCheckMemory(t *testing.T) {
	const mb = 1024 * 1024
	newPool := func(usedMB uint64, supported bool) *Pool {
		return &Pool{
			config:    &config.Config{MaxMemoryMB: 1000},
			available: make(chan *rod.Browser, 1),
			stopCh:    make(chan struct{}),
			readMemory: func() (memorySample, bool) {
				return memorySample{bytes: usedMB * mb, source: "test"}, supported
			},
		}
	}
	start := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

	t.Run("under the limit never recycles", func(t *testing.T) {
		p := newPool(999, true)
		last, supported := p.checkMemory(start, time.Time{})
		if !supported || !last.IsZero() {
			t.Errorf("checkMemory = (%v, %v), want no recycle and supported", last, supported)
		}
	})

	t.Run("exactly at the limit does not recycle", func(t *testing.T) {
		p := newPool(1000, true)
		if last, _ := p.checkMemory(start, time.Time{}); !last.IsZero() {
			t.Error("recycled at exactly the limit")
		}
	})

	t.Run("over the limit recycles once, then respects the cooldown", func(t *testing.T) {
		p := newPool(1500, true)

		last, _ := p.checkMemory(start, time.Time{})
		if !last.Equal(start) {
			t.Fatalf("first over-limit check did not recycle (last = %v)", last)
		}

		// Usage stays high on every later tick inside the cooldown
		for tick := memoryCheckInterval; tick < memoryRecycleCooldown; tick += memoryCheckInterval {
			again, _ := p.checkMemory(start.Add(tick), last)
			if !again.Equal(start) {
				t.Fatalf("recycled again %v after the previous recycle, inside the %v cooldown", tick, memoryRecycleCooldown)
			}
		}

		after, _ := p.checkMemory(start.Add(memoryRecycleCooldown), last)
		if !after.Equal(start.Add(memoryRecycleCooldown)) {
			t.Error("did not recycle again once the cooldown had passed")
		}
	})

	t.Run("unsupported platform reports it and never recycles", func(t *testing.T) {
		p := newPool(999999, false)
		last, supported := p.checkMemory(start, time.Time{})
		if supported || !last.IsZero() {
			t.Errorf("checkMemory = (%v, %v), want unsupported and no recycle", last, supported)
		}
	})
}

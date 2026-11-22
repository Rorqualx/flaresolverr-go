package browser

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/config"
)

// The launch-timeout path in launchAndConnect went untested until a data race
// between rod's launcher.Launch and Kill surfaced in CI (PR #51). It went
// untested because the deadline was a hard-coded 60s const: Pool.launchTimeout
// is the seam that lets this run in milliseconds instead.

// fakeHungBrowser writes an executable that stands in for a Chrome which
// starts and then never reports its DevTools URL -- the exact hang the launch
// deadline exists for. It ignores every flag rod passes it.
//
// No real Chromium is involved, so the test is hermetic and cheap in CI. It
// returns the binary's path and the path the binary records its own PID to.
func fakeHungBrowser(t *testing.T) (bin, pidPath string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the fake browser is a POSIX shell script")
	}

	dir := t.TempDir()
	bin = filepath.Join(dir, "fake-chrome")
	pidPath = filepath.Join(dir, "fake-chrome.pid")

	// exec keeps the recorded PID valid: sleep replaces the shell rather than
	// running as its child, so killing that PID really does stop the process.
	script := "#!/bin/sh\n" +
		"case \"$1\" in --selftest) exit 0 ;; esac\n" +
		"echo $$ > '" + pidPath + "'\n" +
		"exec sleep 300\n"
	//nolint:gosec // G306: a stand-in browser binary has to be executable
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("writing the fake browser: %v", err)
	}

	// t.TempDir() can sit on a noexec mount -- tmpfs defaults to one, which is
	// what forced Leakless(false) on Unraid. Find that out here rather than
	// mistake "permission denied" for a launch timeout.
	//nolint:gosec // G204: bin is this test's own temp file
	if err := exec.Command(bin, "--selftest").Run(); err != nil {
		t.Skipf("cannot execute %s: %v", bin, err)
	}

	// Belt and braces. The test asserts the process is already gone; this only
	// matters if it fails before getting that far.
	t.Cleanup(func() {
		if pid, ok := readPID(pidPath); ok {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
	})

	return bin, pidPath
}

// readPID returns the PID the fake browser recorded, if it got that far.
func readPID(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// processAlive reports whether pid still exists. Signal 0 asks about the
// process without touching it.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func TestLaunchAndConnectTimesOut(t *testing.T) {
	bin, pidPath := fakeHungBrowser(t)

	const launchTimeout = 300 * time.Millisecond

	p := &Pool{
		config:        &config.Config{Headless: true, BrowserPath: bin},
		launchTimeout: launchTimeout,
	}

	start := time.Now()
	browser, err := p.launchAndConnect(context.Background(), p.createLauncher(""))
	elapsed := time.Since(start)

	if browser != nil {
		t.Error("got a browser back from a launch that cannot succeed")
	}
	if err == nil {
		t.Fatal("expected a launch timeout, got a nil error")
	}
	if !strings.Contains(err.Error(), "browser launch timed out") {
		t.Fatalf("got %q, want a launch timeout", err)
	}

	// The injected deadline is the one that fired, not the 60s constant.
	if elapsed > browserLaunchTimeout/4 {
		t.Errorf("launch took %v: the injected %v deadline was ignored", elapsed, launchTimeout)
	}

	// The reaper goroutine finishing is the proof that Launch was unblocked.
	// That is why the timeout branch cancels the launcher's context instead of
	// calling Kill from this goroutine: Kill here would read l.pid while
	// Launch is still writing it.
	reaped := make(chan struct{})
	go func() {
		p.closeWg.Wait()
		close(reaped)
	}()
	select {
	case <-reaped:
	case <-time.After(browserLaunchTimeout):
		t.Fatal("the launcher reaper never finished: Launch is still blocked")
	}

	pid, ok := readPID(pidPath)
	if !ok {
		t.Fatal("the fake browser never recorded a PID, so it never started")
	}

	// A hung browser left alive holds its user-data dir and starves every
	// later launch, so the timeout path has to take the process with it.
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("fake browser pid %d is still alive after the launch failed", pid)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestLaunchTimeoutOrDefault(t *testing.T) {
	tests := []struct {
		name  string
		field time.Duration
		want  time.Duration
	}{
		{"unset, as in a pool built directly by a test", 0, browserLaunchTimeout},
		{"negative", -time.Second, browserLaunchTimeout},
		{"as NewPool sets it", browserLaunchTimeout, browserLaunchTimeout},
		{"injected by a test", 250 * time.Millisecond, 250 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Pool{launchTimeout: tt.field}
			if got := p.launchTimeoutOrDefault(); got != tt.want {
				t.Errorf("launchTimeoutOrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewPoolSetsLaunchTimeout guards the production default: the seam is only
// safe because the real constructor fills it in. A pool size of zero launches
// no browsers, so this costs nothing.
func TestNewPoolSetsLaunchTimeout(t *testing.T) {
	pool, err := NewPool(&config.Config{Headless: true, BrowserPoolSize: 0})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if pool.launchTimeout != browserLaunchTimeout {
		t.Errorf("NewPool left launchTimeout = %v, want %v", pool.launchTimeout, browserLaunchTimeout)
	}
}

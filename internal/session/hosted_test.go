package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// navigate loads url on the session page and returns the page text.
func navigate(t *testing.T, sess *Session, url string) string {
	t.Helper()
	page, release := sess.AcquirePageWithRelease()
	if page == nil {
		t.Fatal("session page unavailable")
	}
	defer release()

	p := page.Timeout(30 * time.Second)
	if err := p.Navigate(url); err != nil {
		t.Fatalf("navigate %s: %v", url, err)
	}
	if err := p.WaitLoad(); err != nil {
		t.Fatalf("wait load %s: %v", url, err)
	}
	res, err := p.Eval(`() => document.cookie`)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	return res.Value.Str()
}

func setCookie(t *testing.T, sess *Session, value string) {
	t.Helper()
	page, release := sess.AcquirePageWithRelease()
	if page == nil {
		t.Fatal("session page unavailable")
	}
	defer release()
	_, err := page.Timeout(10*time.Second).Eval(`(v) => { document.cookie = v + "; max-age=3600; path=/" }`, value)
	if err != nil {
		t.Fatalf("set cookie: %v", err)
	}
}

func hostState(m *Manager) (browser *rod.Browser, sessions int) {
	m.hostMu.Lock()
	defer m.hostMu.Unlock()
	if m.host == nil {
		return nil, 0
	}
	return m.host.browser, m.host.sessions
}

// TestHostedSessionsDoNotUsePoolBrowsers verifies sessions no longer take
// browsers out of the request pool, and that the shared session browser lives
// exactly as long as there are hosted sessions.
func TestHostedSessionsDoNotUsePoolBrowsers(t *testing.T) {
	pool, manager := newPoolAndManager(t)
	manager.config.MaxSessions = 4
	ctx := context.Background()

	if b, _ := hostState(manager); b != nil {
		t.Fatal("session browser started before any session exists")
	}

	ids := []string{"hosted-a", "hosted-b", "hosted-c", "hosted-d"} // more than the pool size of 2
	for _, id := range ids {
		sess, err := manager.CreateIsolated(ctx, id, 0, "")
		if err != nil {
			t.Fatalf("CreateIsolated(%s): %v", id, err)
		}
		if !sess.Hosted() {
			t.Errorf("session %s is not hosted", id)
		}
	}

	if got := pool.Available(); got != pool.Size() {
		t.Errorf("Available() = %d with %d sessions open, want %d (sessions must not pin pool browsers)", got, len(ids), pool.Size())
	}
	host, count := hostState(manager)
	if host == nil || count != len(ids) {
		t.Fatalf("session browser sessions = %d, want %d on one shared browser", count, len(ids))
	}

	if _, err := manager.CreateIsolated(ctx, "hosted-e", 0, ""); !errors.Is(err, types.ErrTooManySessions) {
		t.Errorf("CreateIsolated over the limit = %v, want ErrTooManySessions", err)
	}
	if _, err := manager.CreateIsolated(ctx, "hosted-a", 0, ""); !errors.Is(err, types.ErrSessionAlreadyExists) {
		t.Errorf("CreateIsolated duplicate = %v, want ErrSessionAlreadyExists", err)
	}
	if _, count := hostState(manager); count != len(ids) {
		t.Errorf("session browser count = %d after rejected creates, want %d", count, len(ids))
	}

	for _, id := range ids {
		if err := manager.Destroy(id); err != nil {
			t.Fatalf("Destroy(%s): %v", id, err)
		}
	}
	if b, count := hostState(manager); b != nil || count != 0 {
		t.Errorf("session browser still running after the last session was destroyed (count %d)", count)
	}
	if got := pool.Stats().Released; got != 0 {
		t.Errorf("pool Released = %d, want 0 (hosted sessions never touch the pool)", got)
	}
}

// TestHostedSessionsHaveSeparateCookies verifies each hosted session has its
// own cookie store even though they share one browser process.
func TestHostedSessionsHaveSeparateCookies(t *testing.T) {
	_, manager := newPoolAndManager(t)
	manager.config.MaxSessions = 2
	ctx := context.Background()

	first, err := manager.CreateIsolated(ctx, "cookies-a", 0, "")
	if err != nil {
		t.Fatalf("CreateIsolated: %v", err)
	}
	second, err := manager.CreateIsolated(ctx, "cookies-b", 0, "")
	if err != nil {
		t.Fatalf("CreateIsolated: %v", err)
	}

	const site = "https://example.com/"
	navigate(t, first, site)
	setCookie(t, first, "owner=session-a")

	if got := navigate(t, first, site); !strings.Contains(got, "owner=session-a") {
		t.Fatalf("session A lost its own cookie: %q", got)
	}
	if got := navigate(t, second, site); strings.Contains(got, "owner=session-a") {
		t.Errorf("session B can read session A's cookie: %q", got)
	}
}

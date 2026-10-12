// Package captcha — oopif.go adds out-of-process-iframe (OOPIF) capture for the
// turnstile.render() interceptor.
//
// WHY: On a Cloudflare *managed challenge* the Turnstile widget renders inside a
// cross-origin, out-of-process iframe (challenges.cloudflare.com). That target is
// invisible to querySelector, Page.getFrameTree, Target.getTargets and a pierced
// DOM of the main target — and go-rod's Page.EachEvent filters by the page's own
// sessionID, so the child Target.attachedToTarget events never reach it (see
// browser.go:391). The render params (sitekey/action/cData/chlPageData) therefore
// exist only inside that separate target.
//
// HOW: We drop to raw CDP beneath go-rod. We enable Target.setAutoAttach on the
// PAGE's session (so its OOPIF children attach to us, each paused via
// waitForDebuggerOnStart) and listen on Browser.EachEvent — the BROWSER-level
// stream that, unlike Page.EachEvent, is not scoped to a single sessionID. For
// each attached child we register the interceptor at document_start via
// Page.addScriptToEvaluateOnNewDocument, then release it with
// Runtime.runIfWaitingForDebugger. This chain was validated end-to-end against a
// real OOPIF (Document-Isolation-Policy fixture), capturing all four managed-
// challenge params incl. chlPageData. See docs/INVESTIGATION-issue-11-oopif-probes.md.
package captcha

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

const (
	// oopifCDPTimeout bounds one raw CDP command.
	oopifCDPTimeout = 8 * time.Second

	// maxOOPIFChildren bounds how many child sessions are tracked per page. A
	// challenge page has one or two; an ad-heavy page can attach dozens.
	maxOOPIFChildren = 64

	// oopifStopTimeout bounds how long stop waits for the listener to exit.
	oopifStopTimeout = 2 * time.Second
)

// oopifAutoAttachParams attaches to directly-related targets (iframes/OOPIFs),
// over a single flat connection, pausing each new target until we resume it.
var oopifAutoAttachParams = map[string]any{
	"autoAttach":             true,
	"waitForDebuggerOnStart": true,
	"flatten":                true,
}

// oopifAutoAttachOff undoes oopifAutoAttachParams.
var oopifAutoAttachOff = map[string]any{
	"autoAttach":             false,
	"waitForDebuggerOnStart": false,
	"flatten":                true,
}

// oopifState tracks the browser-level auto-attach capture for one page's OOPIF
// children. It is created per InstallTurnstileInterceptor and stopped by
// RemoveTurnstileInterceptor.
type oopifState struct {
	browser     *rod.Browser
	pageSession proto.TargetSessionID
	cancel      context.CancelFunc
	done        chan struct{} // closed when the listener goroutine has exited

	mu       sync.Mutex
	children []proto.TargetSessionID
}

// rawCDP sends a session-scoped CDP command beneath go-rod, bounded by ctx and
// by a timeout of its own.
func rawCDP(ctx context.Context, b *rod.Browser, sid proto.TargetSessionID, method string, params interface{}) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, oopifCDPTimeout)
	defer cancel()
	return b.Call(ctx, string(sid), method, params)
}

// installOOPIFCapture enables auto-attach on the page session and starts the
// browser-level listener. Always returns a non-nil state (with no listener if
// setup fails) so the caller's presence check still works for the main frame.
//
// The listener lives until stop() or until ctx ends, whichever is first, so a
// request that is abandoned takes its listener with it.
func installOOPIFCapture(ctx context.Context, page *rod.Page) *oopifState {
	browser := page.Browser()
	st := &oopifState{pageSession: page.SessionID}
	if browser == nil {
		return st
	}
	st.browser = browser

	if _, err := rawCDP(ctx, browser, page.SessionID, "Target.setAutoAttach", oopifAutoAttachParams); err != nil {
		log.Debug().Err(err).Msg("OOPIF capture: setAutoAttach on page session failed; main-frame capture only")
		return st
	}

	listenCtx, cancel := context.WithCancel(ctx)
	st.cancel = cancel
	st.done = make(chan struct{})

	wait := browser.Context(listenCtx).EachEvent(
		func(e *proto.TargetAttachedToTarget, envelope proto.TargetSessionID) bool {
			st.handleAttached(listenCtx, e, envelope)
			return false // keep listening until the context ends
		},
		func(e *proto.TargetDetachedFromTarget) bool {
			st.untrack(e.SessionID)
			return false
		},
	)
	go func() {
		defer close(st.done)
		wait()
	}()
	return st
}

// belongs reports whether an attach event on `envelope` is for one of our page's
// targets (its own session, or a previously-seen child for nested OOPIFs).
func (st *oopifState) belongs(envelope proto.TargetSessionID) bool {
	if envelope == st.pageSession {
		return true
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, c := range st.children {
		if c == envelope {
			return true
		}
	}
	return false
}

// track remembers a child session. It reports false, and remembers nothing,
// when the page already has maxOOPIFChildren live children.
func (st *oopifState) track(child proto.TargetSessionID) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.children) >= maxOOPIFChildren {
		return false
	}
	st.children = append(st.children, child)
	return true
}

// untrack forgets a child session whose target has gone away, so later lookups
// do not send commands to a dead session.
func (st *oopifState) untrack(child proto.TargetSessionID) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, c := range st.children {
		if c == child {
			st.children = append(st.children[:i], st.children[i+1:]...)
			return
		}
	}
}

// snapshot returns a copy of the tracked child sessions.
func (st *oopifState) snapshot() []proto.TargetSessionID {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]proto.TargetSessionID(nil), st.children...)
}

// handleAttached registers the interceptor at document_start in a freshly-
// attached, paused child and releases it. runIfWaitingForDebugger MUST always run
// or the child hangs.
//
// Processed SYNCHRONOUSLY on the event loop: this gives natural backpressure on
// the single CDP connection. A concurrent (goroutine-per-child) variant flooded
// the connection on ad-heavy pages and pushed a normal solve from ~17s to ~98s.
// We also do NOT recurse auto-attach into grandchildren — Cloudflare's managed-
// challenge Turnstile is a DIRECT child of the main page, and recursing explodes
// the paused-target count on pages full of nested ad iframes.
func (st *oopifState) handleAttached(ctx context.Context, e *proto.TargetAttachedToTarget, envelope proto.TargetSessionID) {
	if e == nil || e.TargetInfo == nil || !st.belongs(envelope) {
		return
	}
	child := e.SessionID
	b := st.browser

	if st.track(child) {
		// Page domain must be enabled for addScriptToEvaluateOnNewDocument to work.
		// Ignore error: the next call reports the failure that matters.
		_, _ = rawCDP(ctx, b, child, "Page.enable", nil)
		if _, err := rawCDP(ctx, b, child, "Page.addScriptToEvaluateOnNewDocument",
			map[string]any{"source": turnstileInterceptorJS}); err != nil {
			log.Debug().Err(err).Msg("OOPIF capture: addScriptToEvaluateOnNewDocument failed")
		}
	} else {
		log.Debug().Int("limit", maxOOPIFChildren).Msg("OOPIF capture: child limit reached; releasing child without instrumenting it")
	}

	if _, err := rawCDP(ctx, b, child, "Runtime.runIfWaitingForDebugger", nil); err != nil {
		log.Debug().Err(err).Msg("OOPIF capture: runIfWaitingForDebugger failed (child may stay paused)")
	}
}

// params returns the first captured render params (carrying a sitekey) found in
// any tracked OOPIF child session.
func (st *oopifState) params(ctx context.Context) (*ChallengeParams, bool) {
	if st == nil || st.browser == nil {
		return nil, false
	}
	for _, child := range st.snapshot() {
		if p, ok := readSessionChallengeParams(ctx, st.browser, child); ok {
			return p, true
		}
	}
	return nil, false
}

// injectCallback delivers a solved token to any OOPIF child that captured a
// callback. Returns true if a child reported the callback fired.
func (st *oopifState) injectCallback(ctx context.Context, expr string) bool {
	if st == nil || st.browser == nil {
		return false
	}
	for _, child := range st.snapshot() {
		raw, err := rawCDP(ctx, st.browser, child, "Runtime.evaluate",
			map[string]any{"expression": expr, "returnByValue": true})
		if err != nil {
			continue
		}
		if evalResultBool(raw) {
			return true
		}
	}
	return false
}

// stop ends the listener and waits, briefly, for its goroutine to exit.
func (st *oopifState) stop() {
	if st == nil || st.cancel == nil {
		return
	}
	st.cancel()

	timer := time.NewTimer(oopifStopTimeout)
	defer timer.Stop()
	select {
	case <-st.done:
	case <-timer.C:
		log.Debug().Msg("OOPIF capture: listener did not exit in time")
	}

	// Turn auto-attach back off. With the listener gone nothing would release a
	// child paused by waitForDebuggerOnStart, so a page that outlives this
	// request (a session) would hang on its next cross-origin iframe. The
	// request's context may already be over, hence a short one of our own.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), oopifStopTimeout)
	defer cancel()
	if _, err := rawCDP(cleanupCtx, st.browser, st.pageSession, "Target.setAutoAttach", oopifAutoAttachOff); err != nil {
		log.Debug().Err(err).Msg("OOPIF capture: failed to disable auto-attach (page may already be closed)")
	}
}

// readSessionChallengeParams evaluates window.__cfChallengeParams in a session.
func readSessionChallengeParams(ctx context.Context, b *rod.Browser, sid proto.TargetSessionID) (*ChallengeParams, bool) {
	raw, err := rawCDP(ctx, b, sid, "Runtime.evaluate", map[string]any{
		"expression":    `JSON.stringify(window.__cfChallengeParams || null)`,
		"returnByValue": true,
	})
	if err != nil {
		return nil, false
	}
	s, ok := evalResultString(raw)
	if !ok {
		return nil, false
	}
	return parseChallengeParams([]byte(s))
}

// evalResultString extracts a JSON-string result.value from a Runtime.evaluate
// response (the value is itself a JSON-encoded string from JSON.stringify).
func evalResultString(raw []byte) (string, bool) {
	var out struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return "", false
	}
	var s string
	if json.Unmarshal(out.Result.Value, &s) != nil || s == "" || s == "null" {
		return "", false
	}
	return s, true
}

// evalResultBool extracts a boolean result.value from a Runtime.evaluate response.
func evalResultBool(raw []byte) bool {
	var out struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return false
	}
	return out.Result.Value
}

// parseChallengeParams unmarshals the captured params JSON and requires a sitekey.
func parseChallengeParams(jsonStr []byte) (*ChallengeParams, bool) {
	var p ChallengeParams
	if err := json.Unmarshal(jsonStr, &p); err != nil {
		return nil, false
	}
	if !p.hasSiteKey() {
		return nil, false
	}
	return &p, true
}

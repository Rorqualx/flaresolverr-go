// Command probe-oopif is a throwaway investigation harness for GitHub issue #11
// Part 2 (managed-challenge Turnstile param capture across a cross-origin
// out-of-process iframe / OOPIF).
//
// It is NOT built into the production image (the main Dockerfile only builds
// ./cmd/flaresolverr). It empirically tests the deep-research claims about how
// to reach CF's OOPIF child target via raw CDP beneath go-rod:
//
//	claim 1 — with Target.setAutoAttach{autoAttach,flatten,waitForDebuggerOnStart},
//	          child Target.attachedToTarget events arrive on the BROWSER-level
//	          event stream (Browser.EachEvent, empty sessionID) but are dropped by
//	          Page.EachEvent (browser.go:391 sessionID filter).
//	claim 2 — auto-attach actually reaches a challenges.cloudflare.com OOPIF child.
//	claim 3 — Page.addScriptToEvaluateOnNewDocument injected into the paused child
//	          session at document_start, then Runtime.runIfWaitingForDebugger,
//	          captures the render params (sitekey/action/cData/chlPageData).
//	claim 4 — (open question) whether Network requests to the challenge-platform
//	          carry the params, recoverable without JS injection.
//
// It prints a single JSON object (raw evidence + computed pass/fail) to stdout.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// turnstileInterceptorJS is copied verbatim from internal/captcha/intercept.go so
// the probe exercises the exact production hook (it is unexported there).
const turnstileInterceptorJS = `
(() => {
  try {
    if (window.__cfInterceptorInstalled) return;
    window.__cfInterceptorInstalled = true;

    const capture = (params) => {
      try {
        if (!params || !params.sitekey) return;
        window.__cfChallengeParams = {
          sitekey: params.sitekey,
          action: params.action || '',
          cData: params.cData || '',
          chlPageData: params.chlPageData || ''
        };
        if (typeof params.callback === 'function') {
          window.__cfChallengeCallback = params.callback;
        }
      } catch (e) {}
    };

    const hook = () => {
      try {
        const ts = window.turnstile;
        if (ts && typeof ts.render === 'function' && !ts.render.__cfHooked) {
          const orig = ts.render.bind(ts);
          const wrapped = function(container, params) {
            capture(params);
            return orig(container, params);
          };
          wrapped.__cfHooked = true;
          ts.render = wrapped;
        }
      } catch (e) {}
    };

    let _ts = window.turnstile;
    try {
      Object.defineProperty(window, 'turnstile', {
        configurable: true,
        get() { return _ts; },
        set(v) { _ts = v; hook(); }
      });
    } catch (e) {}

    hook();
    let n = 0;
    const iv = setInterval(() => { hook(); if (++n > 3000) clearInterval(iv); }, 10);
  } catch (e) {}
})();
`

// challengeParams mirrors captcha.ChallengeParams.
type challengeParams struct {
	SiteKey  string `json:"sitekey"`
	Action   string `json:"action"`
	CData    string `json:"cData"`
	PageData string `json:"chlPageData"`
}

func (p *challengeParams) hasSiteKey() bool { return p != nil && p.SiteKey != "" }

// childRecord is one attached target observed during the run.
type childRecord struct {
	ChildSessionID       string            `json:"child_session_id"`
	EnvelopeSessionID    string            `json:"envelope_session_id"` // session the attach event ARRIVED on ("" == root/browser)
	TargetID             string            `json:"target_id"`
	Type                 string            `json:"type"`
	URL                  string            `json:"url"`
	WaitingForDebugger   bool              `json:"waiting_for_debugger"`
	SeenAtBrowserLevel   bool              `json:"seen_at_browser_level"`
	SeenAtPageLevel      bool              `json:"seen_at_page_level"`
	IsCloudflareOOPIF    bool              `json:"is_cloudflare_oopif"`
	InjectSteps          map[string]string `json:"inject_steps,omitempty"` // step -> "ok" | error
	InterceptorInstalled bool              `json:"interceptor_installed"`  // proves document_start injection ran IN the child
	Params               *challengeParams  `json:"params,omitempty"`
}

// netRecord is one challenge-platform network request (claim 4).
type netRecord struct {
	EnvelopeSessionID string `json:"envelope_session_id"`
	Method            string `json:"method"`
	URL               string `json:"url"`
	HasPostData       bool   `json:"has_post_data"`
	PostData          string `json:"post_data,omitempty"`
	ParamsInRequest   bool   `json:"params_in_request"`
}

type report struct {
	Target         string           `json:"target"`
	Headless       bool             `json:"headless"`
	SitePerProcess bool             `json:"site_per_process"`
	Proxy          string           `json:"proxy,omitempty"`
	Stage          string           `json:"stage"` // last lifecycle milestone reached (pinpoints hangs)
	PageSessionID  string           `json:"page_session_id"`
	AllTargets     []string         `json:"all_targets"`        // "type url" from Target.getTargets
	Discovered     []string         `json:"discovered_targets"` // "type url" from Target.targetCreated (discovery)
	Frames         []string         `json:"frames"`             // "url" from Page.getFrameTree (main page)
	ChromeFlags    string           `json:"chrome_flags"`
	Children       []*childRecord   `json:"children"`
	ChallengeReqs  []*netRecord     `json:"challenge_requests"`
	TopFrameParams *challengeParams `json:"top_frame_params,omitempty"`
	Scores         map[string]bool  `json:"scores"`
	Notes          []string         `json:"notes"`
}

func isChallengeURL(u string) bool {
	u = strings.ToLower(u)
	return strings.Contains(u, "challenges.cloudflare.com") ||
		strings.Contains(u, "/cdn-cgi/challenge-platform") ||
		strings.Contains(u, "turnstile")
}

func main() {
	target := flag.String("url", "https://nowsecure.nl", "target URL to probe")
	headless := flag.Bool("headless", true, "run headless (false needs an X display / xvfb)")
	settle := flag.Duration("settle", 18*time.Second, "wait after navigation for the challenge to render")
	bin := flag.String("bin", "/usr/bin/chromium-browser", "chromium binary path")
	siteIso := flag.Bool("site-per-process", false, "force site isolation so cross-origin iframes become OOPIFs")
	maxRun := flag.Duration("maxrun", 90*time.Second, "hard watchdog: always emit and exit by this deadline")
	iframeSrc := flag.String("iframe-src", "", "if set, inject a cross-origin iframe with this src to force a controlled OOPIF")
	proxy := flag.String("proxy", "", "chromium --proxy-server value, e.g. socks5://127.0.0.1:9050 (flagged egress to force the managed tier)")
	fixture := flag.Bool("fixture", false, "serve a local COOP/COEP/Document-Isolation-Policy cross-site OOPIF that simulates CF turnstile.render with chlPageData")
	flag.Parse()

	// Local OOPIF fixture: deterministically reproduce a cross-site, process-isolated
	// iframe that calls turnstile.render(el, {sitekey,action,cData,chlPageData}) just
	// like a Cloudflare managed challenge — no Cloudflare or flagged IP needed.
	if *fixture {
		startFixtureServers()
		*target = "http://127.0.0.1:7000/"
		*iframeSrc = ""
		*siteIso = true // fixture relies on isolation
	}

	rep := &report{Target: *target, Headless: *headless, SitePerProcess: *siteIso, Proxy: *proxy, Scores: map[string]bool{}}

	// Watchdog FIRST — before launching Chromium — so even a hang in launch/connect
	// (e.g. a dead-slow proxy) can never run past maxRun without emitting + exiting.
	var mu sync.Mutex
	var finishOnce sync.Once
	finish := func(code int) {
		finishOnce.Do(func() { mu.Lock(); emit(rep); mu.Unlock() })
		os.Exit(code)
	}
	go func() {
		time.Sleep(*maxRun)
		mu.Lock()
		rep.Notes = append(rep.Notes, "WATCHDOG TIMEOUT: "+maxRun.String())
		mu.Unlock()
		finish(3)
	}()
	stage := func(s string) { mu.Lock(); rep.Stage = s; mu.Unlock() }
	stage("launching")

	l := launcher.New().Bin(*bin).Headless(*headless).
		Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage")
	if *proxy != "" {
		l = l.Set("proxy-server", *proxy)
	}
	if *siteIso {
		// CRITICAL: go-rod's default launcher sets --disable-features=site-per-process,
		// which collapses cross-origin iframes into the parent process (no OOPIF).
		// Override disable-features to drop site-per-process, then enable it.
		l = l.Set("disable-features", "TranslateUI")
		l = l.Delete("disable-site-isolation-trials")
		l = l.Set("site-per-process")
		l = l.Set("isolate-origins", "https://example.com,https://challenges.cloudflare.com,http://127.0.0.2:7001")
		if *headless {
			l = l.Set("headless", "new") // old headless lacks full OOPIF/site-isolation support
		}
	}
	rep.ChromeFlags = strings.Join(l.FormatArgs(), " ")
	controlURL, err := l.Launch()
	if err != nil {
		fail(rep, fmt.Sprintf("launch: %v", err))
	}

	stage("launched")
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		fail(rep, fmt.Sprintf("connect: %v", err))
	}
	defer func() { _ = browser.Close() }()

	stage("connected")
	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		fail(rep, fmt.Sprintf("create page: %v", err))
	}
	rep.PageSessionID = string(page.SessionID)
	stage("page_created")

	children := map[string]*childRecord{} // keyed by child session id
	pageSeen := map[string]bool{}         // child session ids seen at page level

	rawCall := func(sid, method string, params interface{}) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return browser.Call(ctx, sid, method, params)
	}

	autoAttachParams := map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}

	// inject the interceptor into a paused child and recurse auto-attach.
	injectChild := func(rec *childRecord) {
		steps := map[string]string{}
		step := func(name, method string, params interface{}) {
			if _, e := rawCall(rec.ChildSessionID, method, params); e != nil {
				steps[name] = e.Error()
			} else {
				steps[name] = "ok"
			}
		}
		step("page.enable", "Page.enable", nil)
		step("addScript", "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": turnstileInterceptorJS})
		step("child.setAutoAttach", "Target.setAutoAttach", autoAttachParams) // recurse into grandchild OOPIFs
		step("network.enable", "Network.enable", nil)
		step("runIfWaiting", "Runtime.runIfWaitingForDebugger", nil)
		mu.Lock()
		rec.InjectSteps = steps
		mu.Unlock()
	}

	// Browser-level stream: catches events of ALL sessions (empty sessionID filter).
	browserWait := browser.EachEvent(
		func(e *proto.TargetAttachedToTarget, envelope proto.TargetSessionID) bool {
			ti := e.TargetInfo
			rec := &childRecord{
				ChildSessionID:     string(e.SessionID),
				EnvelopeSessionID:  string(envelope),
				TargetID:           string(ti.TargetID),
				Type:               string(ti.Type),
				URL:                ti.URL,
				WaitingForDebugger: e.WaitingForDebugger,
				SeenAtBrowserLevel: true,
				IsCloudflareOOPIF:  isChallengeURL(ti.URL),
			}
			mu.Lock()
			children[rec.ChildSessionID] = rec
			mu.Unlock()
			go injectChild(rec) // inject while paused; runIfWaitingForDebugger releases it
			return false
		},
		func(e *proto.TargetTargetCreated, envelope proto.TargetSessionID) bool {
			if e.TargetInfo == nil {
				return false
			}
			mu.Lock()
			rep.Discovered = append(rep.Discovered, string(e.TargetInfo.Type)+" "+e.TargetInfo.URL)
			mu.Unlock()
			return false
		},
		func(e *proto.NetworkRequestWillBeSent, envelope proto.TargetSessionID) bool {
			if e.Request == nil || !isChallengeURL(e.Request.URL) {
				return false
			}
			pd := e.Request.PostData
			inReq := strings.Contains(pd, "cData") || strings.Contains(pd, "chlPageData") ||
				strings.Contains(e.Request.URL, "chlPageData")
			mu.Lock()
			rep.ChallengeReqs = append(rep.ChallengeReqs, &netRecord{
				EnvelopeSessionID: string(envelope),
				Method:            e.Request.Method,
				URL:               e.Request.URL,
				HasPostData:       e.Request.HasPostData,
				PostData:          truncate(pd, 2000),
				ParamsInRequest:   inReq,
			})
			mu.Unlock()
			return false
		},
	)
	go browserWait()

	// Page-level stream: scoped to the page sessionID. Tests whether go-rod's
	// Page.EachEvent surfaces the SAME child attach events (claim 1).
	pageWait := page.EachEvent(func(e *proto.TargetAttachedToTarget) bool {
		mu.Lock()
		pageSeen[string(e.SessionID)] = true
		mu.Unlock()
		return false
	})
	go pageWait()

	stage("listeners_up")
	// Let the listeners spin up before we enable auto-attach.
	time.Sleep(300 * time.Millisecond)

	// Discovery surfaces ALL targets (incl. iframe-type OOPIFs) regardless of
	// auto-attach — distinguishes "no OOPIF exists" from "OOPIF exists, attach missed it".
	if _, e := rawCall("", "Target.setDiscoverTargets", map[string]any{"discover": true}); e != nil {
		rep.Notes = append(rep.Notes, "setDiscoverTargets: "+e.Error())
	}

	// Enable auto-attach at BOTH scopes: root (top-level targets) and the page
	// session (its OOPIF children). Record any error but keep going.
	if _, e := rawCall("", "Target.setAutoAttach", autoAttachParams); e != nil {
		rep.Notes = append(rep.Notes, "root setAutoAttach: "+e.Error())
	}
	if _, e := rawCall(rep.PageSessionID, "Target.setAutoAttach", autoAttachParams); e != nil {
		rep.Notes = append(rep.Notes, "page setAutoAttach: "+e.Error())
	}

	// Install the top-frame interceptor on the page session too (mirrors production).
	if _, e := rawCall(rep.PageSessionID, "Page.enable", nil); e != nil {
		rep.Notes = append(rep.Notes, "page.enable: "+e.Error())
	}
	if _, e := rawCall(rep.PageSessionID, "Page.addScriptToEvaluateOnNewDocument",
		map[string]any{"source": turnstileInterceptorJS}); e != nil {
		rep.Notes = append(rep.Notes, "page addScript: "+e.Error())
	}

	// Navigate and let the challenge render.
	stage("navigating")
	if err := page.Timeout(45 * time.Second).Navigate(*target); err != nil {
		rep.Notes = append(rep.Notes, "navigate: "+err.Error())
	}
	stage("navigated")

	// Controlled OOPIF: inject a cross-origin iframe so we can validate the
	// auto-attach + document_start injection mechanism independent of Cloudflare
	// (which won't render its widget from Huey's clean IP / headless).
	if *iframeSrc != "" {
		time.Sleep(2 * time.Second)
		js := `(() => { const f = document.createElement('iframe'); f.src = ` +
			mustJSON(*iframeSrc) + `; document.body.appendChild(f); return true; })()`
		if _, e := rawCall(rep.PageSessionID, "Runtime.evaluate",
			map[string]any{"expression": js, "returnByValue": true}); e != nil {
			rep.Notes = append(rep.Notes, "inject iframe: "+e.Error())
		}
	}

	time.Sleep(*settle)
	stage("settled")

	// Read captured params from the top frame and every child session.
	rep.TopFrameParams = readParams(rawCall, rep.PageSessionID)

	// Snapshot under lock, then do the (blocking) CDP reads WITHOUT holding mu —
	// otherwise a wedged read would block the watchdog's finish() from emitting.
	mu.Lock()
	snap := make([]*childRecord, 0, len(children))
	for sid, rec := range children {
		rec.SeenAtPageLevel = pageSeen[sid]
		snap = append(snap, rec)
		_ = sid
	}
	rep.Children = snap // publish before reads so a watchdog timeout still has data
	mu.Unlock()
	for _, rec := range snap {
		rec.InterceptorInstalled = readBool(rawCall, rec.ChildSessionID, `!!window.__cfInterceptorInstalled`)
		if p := readParams(rawCall, rec.ChildSessionID); p.hasSiteKey() {
			rec.Params = p
		}
	}

	// Dump the full target list (all types) to reveal topology. Note: OOPIF
	// subframe targets are auto-attach-only and may NOT appear here even so.
	if raw, e := rawCall("", "Target.getTargets", map[string]any{"filter": []map[string]any{{}}}); e == nil {
		var gt struct {
			TargetInfos []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"targetInfos"`
		}
		if json.Unmarshal(raw, &gt) == nil {
			for _, ti := range gt.TargetInfos {
				rep.AllTargets = append(rep.AllTargets, ti.Type+" "+ti.URL)
			}
		}
	}

	// Dump the main page's frame tree to confirm whether the cross-origin
	// Turnstile iframe exists as a frame at all (vs an OOPIF separate target).
	if raw, e := rawCall(rep.PageSessionID, "Page.getFrameTree", map[string]any{}); e == nil {
		var ft struct {
			FrameTree json.RawMessage `json:"frameTree"`
		}
		if json.Unmarshal(raw, &ft) == nil {
			rep.Frames = walkFrames(ft.FrameTree)
		}
	}

	score(rep)
	finish(0)
}

// readParams evaluates window.__cfChallengeParams in a session and returns it.
func readParams(rawCall func(string, string, interface{}) ([]byte, error), sid string) *challengeParams {
	raw, err := rawCall(sid, "Runtime.evaluate", map[string]any{
		"expression":    `JSON.stringify(window.__cfChallengeParams || null)`,
		"returnByValue": true,
	})
	if err != nil {
		return nil
	}
	var out struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	var s string
	if err := json.Unmarshal(out.Result.Value, &s); err != nil || s == "" || s == "null" {
		return nil
	}
	var p challengeParams
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil
	}
	return &p
}

// readBool evaluates a boolean expression in a session.
func readBool(rawCall func(string, string, interface{}) ([]byte, error), sid, expr string) bool {
	raw, err := rawCall(sid, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true})
	if err != nil {
		return false
	}
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

// startFixtureServers serves a parent page (127.0.0.1:7000) embedding a CROSS-SITE
// iframe (127.0.0.2:7001) that simulates Cloudflare's managed-challenge render call.
// Headers force the child into its own process (OOPIF): the parent is
// crossOriginIsolated (COOP+COEP) and the child carries Document-Isolation-Policy +
// COEP + CORP. 127.0.0.1 vs 127.0.0.2 are distinct "sites" so site isolation applies.
func startFixtureServers() {
	parent := http.NewServeMux()
	parent.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><h1>parent</h1>
<iframe src="http://127.0.0.2:7001/child" width="320" height="80"></iframe>
</body></html>`))
	})
	child := http.NewServeMux()
	child.HandleFunc("/child", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Document-Isolation-Policy", "isolate-and-require-corp")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/html")
		// Simulate a Cloudflare managed-challenge render call carrying all 4 params.
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id="cf"></div>
<script>
  window.turnstile = { render: function(el, params){ window.__rendered = params; return 'w1'; } };
  setTimeout(function(){
    try { window.turnstile.render(document.getElementById('cf'), {
      sitekey: '0xFIXTURESITEKEY', action: 'managed',
      cData: 'FIXTURE_CDATA', chlPageData: 'FIXTURE_CHLPAGEDATA',
      callback: function(t){ window.__solved = t; }
    }); } catch(e) { window.__err = String(e); }
  }, 900);
</script></body></html>`))
	})
	parentSrv := &http.Server{Addr: "127.0.0.1:7000", Handler: parent, ReadHeaderTimeout: 5 * time.Second}
	childSrv := &http.Server{Addr: "0.0.0.0:7001", Handler: child, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = parentSrv.ListenAndServe() }()
	go func() { _ = childSrv.ListenAndServe() }()
	time.Sleep(400 * time.Millisecond) // let listeners bind
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func score(rep *report) {
	// claim 1: a non-page (iframe/OOPIF) child caught at browser level that
	// page-level did NOT surface.
	claim1 := false
	// claim 2: an attached child is a cloudflare challenge OOPIF.
	claim2 := false
	// claim 3a: document_start injection actually ran inside an OOPIF child.
	// claim 3b: render params (non-empty sitekey) captured from a child session.
	claim3mech := false
	claim3params := false
	for _, c := range rep.Children {
		if c.Type != "page" && c.SeenAtBrowserLevel && !c.SeenAtPageLevel {
			claim1 = true
		}
		if c.IsCloudflareOOPIF {
			claim2 = true
		}
		if c.Type != "page" && c.InterceptorInstalled {
			claim3mech = true
		}
		if c.Params.hasSiteKey() {
			claim3params = true
		}
	}
	// claim 4: a challenge-platform request carried the params.
	claim4 := false
	for _, n := range rep.ChallengeReqs {
		if n.ParamsInRequest {
			claim4 = true
		}
	}
	rep.Scores["claim1_browser_sees_oopif_page_misses"] = claim1
	rep.Scores["claim2_reaches_cf_oopif"] = claim2
	rep.Scores["claim3a_docstart_inject_ran_in_child"] = claim3mech
	rep.Scores["claim3b_param_capture_in_child"] = claim3params
	rep.Scores["claim4_params_in_network"] = claim4
}

// walkFrames recursively flattens a CDP FrameTree into "url" strings.
func walkFrames(raw json.RawMessage) []string {
	var node struct {
		Frame struct {
			URL string `json:"url"`
		} `json:"frame"`
		ChildFrames []json.RawMessage `json:"childFrames"`
	}
	if json.Unmarshal(raw, &node) != nil {
		return nil
	}
	out := []string{node.Frame.URL}
	for _, c := range node.ChildFrames {
		out = append(out, walkFrames(c)...)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func fail(rep *report, msg string) {
	rep.Notes = append(rep.Notes, "FATAL: "+msg)
	emit(rep)
	os.Exit(1)
}

func emit(rep *report) {
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
}

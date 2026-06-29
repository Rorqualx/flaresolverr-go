// Package captcha provides external CAPTCHA solver integration.
//
// intercept.go captures Cloudflare Turnstile parameters from the
// turnstile.render() call. This matters because the sitekey/action/cData/
// chlPageData are NOT always present as DOM attributes — for widgets rendered by
// script they exist only as the arguments passed to turnstile.render(). We wrap
// render() at document_start and stash the parameters on window.__cfChallengeParams
// so the external solver can submit a correctly-formed task, and keep the real
// callback so a solved token can be delivered the way the challenge expects.
//
// SCOPE / KNOWN LIMITATION — Cloudflare *managed challenges* (the "Just a
// moment..." interstitial, e.g. filecrypt.cc container pages) render Turnstile
// inside a CROSS-ORIGIN, OUT-OF-PROCESS iframe (challenges.cloudflare.com) that
// is itself nested in a CLOSED shadow root. Empirically (see
// docs/INVESTIGATION-issue-11.md) that target is invisible to querySelector,
// Page.getFrameTree, Target.getTargets, and a pierced DOM.getDocument of the main
// target — its real sitekey/params live only inside that separate target. Reaching
// it requires CDP auto-attach (Target.setAutoAttach + Runtime.runIfWaitingForDebugger)
// with document_start injection into the child session. go-rod v0.116 does not
// surface those child attach events to Page.EachEvent, so that path is not wired
// here; this interceptor handles the main-frame / embedded-widget case only.
package captcha

import (
	"encoding/json"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"
)

// ChallengeParams holds the Turnstile parameters captured from turnstile.render().
type ChallengeParams struct {
	SiteKey  string `json:"sitekey"`
	Action   string `json:"action"`
	CData    string `json:"cData"`
	PageData string `json:"chlPageData"`
}

func (p *ChallengeParams) hasSiteKey() bool {
	return p != nil && p.SiteKey != ""
}

// turnstileInterceptorJS wraps turnstile.render to capture its parameters. It is
// injected at document_start so it is in place before the page calls render().
// Idempotent across re-injection and re-render.
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

    // turnstile is usually assigned after our script runs; trap the assignment
    // and also poll briefly as a fallback.
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

// interceptors tracks installed pages so Read/Inject can find them, keyed by
// TargetID. The value is the page's *oopifState (auto-attach capture for its
// out-of-process iframe children); see oopif.go.
var interceptors sync.Map // map[proto.TargetTargetID]*oopifState

// InstallTurnstileInterceptor registers the render() interceptor on the page. It
// must be called BEFORE navigation so the script is present at document_start.
// It also installs OOPIF auto-attach (oopif.go) so managed-challenge Turnstile
// widgets — which render in a cross-origin out-of-process iframe invisible to the
// main frame — are captured too.
// Best-effort: failures are logged but never fatal — DOM/iframe/pierce extraction
// remains as a fallback (see extraction.go).
func InstallTurnstileInterceptor(page *rod.Page) {
	if _, err := page.EvalOnNewDocument(turnstileInterceptorJS); err != nil {
		log.Debug().Err(err).Msg("Failed to register turnstile interceptor")
		return
	}
	interceptors.Store(page.TargetID, installOOPIFCapture(page))
	log.Debug().Msg("Turnstile render interceptor installed (main frame + OOPIF auto-attach)")
}

// loadState returns the page's interceptor state, or (nil, false) if not installed.
func loadState(page *rod.Page) (*oopifState, bool) {
	v, ok := interceptors.Load(page.TargetID)
	if !ok {
		return nil, false
	}
	st, _ := v.(*oopifState)
	return st, true
}

// ReadCapturedChallengeParams returns the parameters captured from
// turnstile.render(). It checks the main frame first, then any captured
// out-of-process iframe (managed-challenge case). Returns (nil, false) if nothing
// usable was captured.
func ReadCapturedChallengeParams(page *rod.Page) (*ChallengeParams, bool) {
	st, ok := loadState(page)
	if !ok {
		return nil, false
	}
	if p, ok := readMainFrameParams(page); ok {
		return p, true
	}
	return st.params()
}

// readMainFrameParams reads window.__cfChallengeParams from the page's main frame.
func readMainFrameParams(page *rod.Page) (*ChallengeParams, bool) {
	res, err := (proto.RuntimeEvaluate{
		Expression:    `JSON.stringify(window.__cfChallengeParams || null)`,
		ReturnByValue: true,
	}).Call(page)
	if err != nil || res == nil || res.Result == nil {
		return nil, false
	}
	raw := res.Result.Value.Str()
	if raw == "" || raw == "null" {
		return nil, false
	}
	return parseChallengeParams([]byte(raw))
}

// InjectCapturedCallback delivers a solved token through the turnstile.render
// callback captured at render time. This is the correct completion path for a
// Turnstile widget — writing the cf-turnstile-response textarea is not always
// enough. It tries the main frame first, then any captured OOPIF child. Returns
// true if the callback fired.
func InjectCapturedCallback(page *rod.Page, token string) bool {
	st, ok := loadState(page)
	if !ok {
		return false
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return false
	}
	expr := `(() => { try { if (typeof window.__cfChallengeCallback === 'function') { window.__cfChallengeCallback(` +
		string(tokenJSON) + `); return true; } } catch (e) {} return false; })()`

	if res, err := (proto.RuntimeEvaluate{Expression: expr, ReturnByValue: true}).Call(page); err == nil &&
		res != nil && res.Result != nil && res.Result.Value.Bool() {
		log.Debug().Msg("Delivered token via captured turnstile callback (main frame)")
		return true
	}
	if st.injectCallback(expr) {
		log.Debug().Msg("Delivered token via captured turnstile callback (OOPIF)")
		return true
	}
	return false
}

// RemoveTurnstileInterceptor clears interception state for a page and stops its
// OOPIF event listener. Safe to call on a page that was never instrumented.
func RemoveTurnstileInterceptor(page *rod.Page) {
	if v, ok := interceptors.LoadAndDelete(page.TargetID); ok {
		if st, _ := v.(*oopifState); st != nil {
			st.stop()
		}
	}
}

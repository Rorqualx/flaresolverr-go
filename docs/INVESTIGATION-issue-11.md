# Investigation: Issue #11 — 2Captcha "turnstile sitekey not found" on filecrypt.cc

## Question
Why does the external 2Captcha fallback fail with `failed to extract sitekey: turnstile sitekey not found`?

Two competing diagnoses:
- **Issue author (Sonnet 4.6):** the extractor reads *static HTML* too early, before JS renders the widget. Fix = switch to CDP `Runtime.evaluate`.
- **Commenter rix1337:** the extractor *already* uses `Runtime.evaluate`. filecrypt serves a Cloudflare **managed challenge** (interstitial) which has **no `data-sitekey`** anywhere in the DOM; the sitekey lives only inside the `turnstile.render(container, params)` call CF's own script makes. So every extraction branch returns empty. Proper fix = intercept `turnstile.render`, capture `sitekey/action/cData/chlPageData`, submit all to 2Captcha as a managed-challenge task, inject token via the captured callback.

## Static code findings (pre-deploy)
- `internal/captcha/extraction.go:96` — `extractSitekeyJS` already runs `proto.RuntimeEvaluate` on the live DOM. The author's proposed fix is a no-op.
- `grep -rn "turnstile.render|chlPageData|pagedata"` over Go source → only a comment. No render interception exists.
- `twoCaptchaTurnstileTask` (twocaptcha.go:92) has `Action`+`Data` but no `pagedata`.
- `TurnstileRequest` (solver.go:35) has no `PageData` field.
- `capSolverMetadata` (capsolver.go:99) has `Action`+`CData` only.
- Extra bug: `SolverChain.Solve` (solver.go:168) builds the request with only SiteKey/PageURL/UserAgent — it never calls the existing `ExtractTurnstileAction`/`ExtractTurnstileCData` helpers, so Action/CData are always empty even for embedded widgets.

## Empirical test plan
Deploy current `main` to Huey (192.168.50.185) in an isolated container and capture the live DOM of the filecrypt challenge page.

- Host: HueyTheDestroyer, Docker 28.1.1, 24 cores / 31GB.
- Isolation: container `flaresolverr-invest`, image `flaresolverr-go:investigation`, port **8195**. Production `flaresolverr` on 8191 untouched.
- Config: `LOG_LEVEL=debug`, `LOG_HTML=true`, `CAPTCHA_FALLBACK_ENABLED=true`, dummy `TWOCAPTCHA_API_KEY` (failure precedes the API call, so no cost / no real key needed), short `MAX_TIMEOUT`.
- Request: `request.get` against a filecrypt.cc Cloudflare-gated URL.

### Decisive checks on the logged HTML / DOM
1. Is there any `data-sitekey` attribute in the top document? (managed challenge → no)
2. Is `.cf-turnstile` present as a page element, or only the CF interstitial (`#challenge-form`, `cf-chl`, `__cf_chl_`, `challenges.cloudflare.com` iframe)?
3. Does the sitekey appear only inside a `turnstile.render(...)` call / CF challenge script?

If (1) empty + (2) interstitial markers + (3) render-only sitekey → rix1337's managed-challenge diagnosis is confirmed and the author's fix is ruled out.

## Results — CONFIRMED (run 2026-06-12 on Huey, image `flaresolverr-go:investigation`, version `invest-issue11`)

### Repro
filecrypt.cc **homepage passed natively in 2.4s** from Huey's IP — no challenge to inspect (same blocker rix1337 hit). Invalid `/Container/<id>.html` IDs 302→`/404.html`; only a valid container page challenges, and the issue's URL is redacted. So the failing path was reproduced against purpose-built **Cloudflare managed-challenge** test targets instead (`2captcha.com/demo/cloudflare-turnstile-challenge`, `scrapingcourse.com/cloudflare-challenge`). Both reproduced issue #11 **byte-for-byte**:

```
INF Native Turnstile solving exhausted, trying external solver native_attempts=1
DBG Failed to extract Turnstile sitekey error="turnstile sitekey not found"
WRN External solver fallback failed error="external solver failed: failed to extract sitekey: turnstile sitekey not found"
ERR Solve failed error="...Challenge resolution timed out..."
```

### Decisive evidence (managed challenge, not stale HTML)
1. **Interstitial, not embedded widget.** Document `status_code=403`, title `Just a moment...` → CF managed challenge.
2. **No `data-sitekey` / `.cf-turnstile` in the live DOM.** FSG's own `page.Has()` checks returned *"shadow host element not found"* for every one of `[data-sitekey]`, `.cf-turnstile`, `#turnstile-wrapper`, `cf-turnstile`, etc. The checkbox was findable **only via full-tree pierce scan** (`nodes_visited=62`) — identical to the issue's log. The elements genuinely don't exist.
3. **Sitekey lives only in the CF challenge-platform iframe URL.** `0x4AAAAAAADnPIDROrmt1Wwj` appears 4× in logs, every time as
   `challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/ov2/av0/rch/<token>/0x4AAA…/light/…` — never as an attribute.
4. **This was post-JS, not too-early.** Extraction ran *after* the checkbox was located and the challenge-platform iframe had loaded. The author's "read the live DOM via `Runtime.evaluate`" fix is already in place (`extraction.go:96`) and changes nothing.

### Verdict
- **rix1337's managed-challenge diagnosis: CONFIRMED.** **Issue author's stale-HTML diagnosis: REFUTED.**
- No 2Captcha API call was ever made (dummy key) — failure precedes submission, so the user is also burning no 2Captcha credit on this path.

### Bonus findings surfaced by the run
- **`LOG_HTML` is a dead flag** — parsed in `config.go:150` into `cfg.LogHTML` but never read anywhere else in the codebase. Setting it does nothing.
- **Even the iframe path can't recover the managed-challenge key.** `extractSitekeyFromURL` (extraction.go:230-247) only matches `/sitekey/` and `sitekey=` forms; the managed-challenge URL embeds the key as `…/rch/<token>/<sitekey>/…`, so it isn't parsed. And a key alone is insufficient anyway — a managed challenge needs `action`/`cData`/`chlPageData` from the `turnstile.render` params (TurnstileTaskCloudflareChallengePage), which nothing captures.

---

## Fix attempt (deployed + tested on Huey)

Implemented and deployed (image `flaresolverr-go:investigation`, versions `invest-fix2`…`invest-final`). All builds/tests green locally; deployed and tested live.

### Landed (correct, testable, no regression)
- **Action/cData/pagedata/userAgent plumbing.** `TurnstileRequest.PageData` added; `SolverChain.Solve` now extracts and passes Action/CData (previously built the request with sitekey/url/UA only and silently dropped them); `twoCaptchaTurnstileTask` gained `pagedata` + `userAgent`. Managed-challenge tasks can now be formed correctly *given* the params.
- **`turnstile.render()` interceptor** (`internal/captcha/intercept.go`) injected at document_start; captures sitekey/action/cData/chlPageData + the real callback for **main-frame / embedded-widget** challenges. Captured params override DOM scraping in `Solve`; token delivery prefers the captured callback.
- **Shadow-pierce sitekey extractor** (`extractSitekeyViaPierce`) — walks the flattened DOM (closed shadow roots + same-process frames) as Method 4.
- **Managed-challenge iframe-URL parser** — `extractSitekeyFromURL` now recovers the sitekey from the `.../rch/<token>/<sitekey>/...` path form (unit-tested).
- **Regression check:** filecrypt.cc homepage still solves in **2.7s** (baseline 2.4s) — interceptor install adds no overhead/breakage to normal solves.

### The wall — managed-challenge params remain uncapturable here
A live frame/target diagnostic (`DiagnoseFrames`) against the stuck 2captcha managed demo (title `Just a moment...`, 403, held the whole solve) showed at external-solve time:
```
DIAG frame   depth=0 url=https://2captcha.com/demo/cloudflare-turnstile-challenge   (only frame)
DIAG target  type=page  url=...                                                     (only target)
DIAG probe   {"hasTurnstile":false,"renderType":"none","captured":null,"iframes":[]}
```
The Turnstile is a **cross-origin, out-of-process iframe nested in a closed shadow root**. Its real sitekey/params live only inside that separate target, invisible to: `querySelector` (closed shadow), `Page.getFrameTree` (OOPIF = different target), `Target.getTargets` (no OOPIF subframe enumeration), and pierce-of-main-target (the `<iframe>` element's `src` is `about:blank`; the real URL is the OOPIF's own document). So neither the pierce extractor nor the main-frame interceptor can see it.

Capturing it requires CDP **auto-attach** (`Target.setAutoAttach` + `Runtime.runIfWaitingForDebugger`) with document_start injection into the **child session**. That was prototyped but **go-rod v0.116 does not surface child `Target.attachedToTarget` events to `Page.EachEvent`**, so it was removed (the `waitForDebuggerOnStart:true` variant also risks leaving a child paused/hung). This is the precise remaining work.

### Remaining work to actually solve managed challenges
1. **OOPIF interception** — bypass go-rod's target management to handle `Target.attachedToTarget` on the page session directly (raw `browser.Event()` subscription or a session-scoped client), inject the interceptor at document_start into the challenges.cloudflare.com child target, and exfiltrate params (binding or poll). This is the linchpin.
2. **End-to-end validation needs a real (paid) 2Captcha key** + a live, reliably-*stuck* managed challenge (e.g. a valid filecrypt.cc `/Container/` URL — the reporter has one; homepage and the 2captcha demo both pass natively from Huey/most clean IPs). The dummy-key runs validate everything up to task submission only.

---

### Reproduce / teardown
```
# on Huey (192.168.50.185):
docker logs --since 15m flaresolverr-invest | sed 's/\x1b\[[0-9;]*m//g' | grep -iE "sitekey|turnstile|external solver"
# isolated build still running on :8195 (prod :8191 untouched). To remove:
docker rm -f flaresolverr-invest && docker rmi flaresolverr-go:investigation
```

# Issue #11 Part 2 — OOPIF param-capture: empirical probe scorecard

**Date:** 2026-06-28 · **Harness:** Huey (`192.168.50.185`), Alpine Chromium 136, go-rod v0.116.2
**Probe:** `cmd/probe-oopif` (raw CDP beneath go-rod via `Browser.Call`/`Browser.EachEvent`), built with `Dockerfile.probe` onto the investigation image. Production container on :8191 untouched.

Goal: validate the deep-research claims about reaching Cloudflare's managed-challenge Turnstile OOPIF and capturing `action/cData/chlPageData`, and score each pass/fail with live evidence.

## Scorecard

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| 1 | `Browser.EachEvent` surfaces child `Target.attachedToTarget` that `Page.EachEvent` drops | **PROVEN (mechanism)** | Every run: the second session created by root `setAutoAttach` arrives on envelope `""` with `seen_at_page_level=false`. Confirms `browser.go:391` sessionID filter. Demonstrated on a *page*-type child; an iframe OOPIF child could not be produced (see below). |
| — | Raw CDP beneath go-rod (`Browser.Call(ctx, sessionID, …)`) drives any session | **PROVEN** | All per-child steps returned `ok`: `Page.enable`, `Page.addScriptToEvaluateOnNewDocument`, `Target.setAutoAttach`, `Network.enable`, `Runtime.runIfWaitingForDebugger`. |
| 3a | document_start injection runs *inside* the attached child | **PROVEN (mechanism)** | Child reports `interceptor_installed=true` (the injected `turnstileInterceptorJS` set `window.__cfInterceptorInstalled`). The `waitForDebuggerOnStart`→inject→`runIfWaitingForDebugger` lifecycle works. |
| 2 | Auto-attach reaches a `challenges.cloudflare.com` OOPIF | **BLOCKED — not validated** | Cannot reproduce a *stuck* managed challenge: `nowsecure.nl` and the Turnstile demo both pass from Huey's clean IP, and no OOPIF could be synthesized (next row). |
| 3b | Capture managed params (`cData/chlPageData`) from the child | **BLOCKED — not validated** | Depends on #2. No managed challenge ⇒ no `turnstile.render` with those fields to capture. |
| 4 | Params recoverable from challenge-platform network requests | **REFUTED (as observed)** | Captured `api.js`, `jsd/main.js`, and the `jsd/oneshot` POST. The POST body is an opaque encoded blob; **no `cData`/`chlPageData` in plaintext** in any captured request (`params_in_request=false`). |

## The decisive blocker: no OOPIF can be produced on this harness

Three independent ways to obtain a cross-origin OOPIF all failed:

1. **Real managed challenge** — `nowsecure.nl` (which normally mints `cf_clearance`) **passed** from Huey's clean IP. Only subresource challenge traffic loaded; no `challenges.cloudflare.com` *target* was attached. (Matches the long-standing harness caveat: a clean IP can't reproduce a stuck managed challenge.)

2. **Cloudflare Turnstile demo widget** — `demo.turnstile.workers.dev` loaded `api.js` but **never created the widget iframe** (frame tree = top page only), headless *and* headful (xvfb).

3. **Synthetic cross-origin iframe** (`example.com`) — appeared in `Page.getFrameTree` but **never became a separate OOPIF target**, across: default, `--site-per-process`, `--isolate-origins`, `--headless=new`, and headful. Root cause found in the launched flags:
   - **go-rod's default launcher sets `--disable-features=site-per-process`** (and `--disable-site-isolation-trials`), collapsing cross-origin iframes into the parent process.
   - Even after overriding those and forcing `--site-per-process` + `--headless=new`, this **Alpine `chromium` build did not isolate** the plain cross-origin iframe (no `targetCreated`, no `attachedToTarget`).

### What this implies for the real fix
- Any OOPIF/auto-attach work **must first override go-rod's `--disable-features=site-per-process`** — otherwise the events can never fire. This was previously unaccounted for and would have made the auto-attach fix silently no-op.
- Cloudflare's managed-challenge iframe becomes an OOPIF via its own COEP/sandbox headers (not site-per-process), which is why it is a separate, pierce-invisible target in production while `example.com` is not. **This still needs a live managed challenge (flagged IP) to validate** — it cannot be reproduced on Huey.

## New candidate path surfaced by the probes (cheaper than auto-attach)
`Page.getFrameTree` **did enumerate the cross-origin child frame** (`example.com`) on the main page session. So for an *in-process* cross-origin iframe, `Page.createIsolatedWorld{frameId}` + `Runtime.evaluate{contextId}` may reach the frame **without any auto-attach**. Worth a dedicated probe — but note it does not solve document_start timing for hooking `render()` on an already-loaded widget, and is moot if CF's iframe is a true OOPIF.

## Strategic conclusion (unchanged, now empirically reinforced)
- The building blocks of the auto-attach fix (browser-level events, raw-CDP per-session calls, document_start child injection) **work**.
- The end-to-end is **gated on a live managed challenge from a flagged IP**, which this harness cannot produce — reinforcing that **clean-egress proxy + clearance-cache (already shipped) dominate**, and OOPIF param-capture remains a low-ROI residual that can only be validated off-harness.

## Retest (2026-06-28/29): reharnessed for claims 2 & 3b

Reharnessed two ways after the first scorecard left claims 2 & 3b blocked.

### ✅ Claim 3b PROVEN via a local OOPIF fixture (and claims 1 & 3a upgraded to a real iframe OOPIF)
`probe-oopif -fixture` serves a parent page (`127.0.0.1:7000`, COOP `same-origin` + COEP `require-corp`) embedding a **cross-site** iframe (`127.0.0.2:7001`) that ships **`Document-Isolation-Policy: isolate-and-require-corp`** + COEP + CORP and calls `turnstile.render(el, {sitekey, action:'managed', cData, chlPageData})` like a CF managed challenge. Result:
- A genuine **`iframe` OOPIF target** was created (DIP forced it **even though plain `--site-per-process` did not** in this Alpine Chromium — the earlier `example.com` test failed only because it sent no isolation headers).
- **Claim 1 ✅** on a real OOPIF: the iframe child arrived on `Browser.EachEvent` with `seen_at_page_level=false`.
- **Claim 3a ✅**: `interceptor_installed=true` inside the OOPIF.
- **Claim 3b ✅**: captured `{sitekey:'0xFIXTURESITEKEY', action:'managed', cData:'FIXTURE_CDATA', chlPageData:'FIXTURE_CHLPAGEDATA'}` — **all four fields incl. `chlPageData`** from the OOPIF child via the document_start render hook.

So the auto-attach + `addScriptToEvaluateOnNewDocument` + `runIfWaitingForDebugger` + render-hook chain is **fully validated against a real OOPIF carrying the managed-challenge param shape**. `Document-Isolation-Policy` is the key to forcing an OOPIF locally without site isolation.

### ⛔ Claim 2 (CF's *real* managed challenge → OOPIF) still not reproduced — and now we know why
Stood up **Tor** on Huey (`tor-socks-proxy`, `tornet` docker network) as flagged egress and ran a diagnostic battery:
- **The "stall" is NOT a CF block.** It's an intermittent **go-rod page-init stall on a *cold* Tor circuit** (Chromium's network service initialises against the proxy during first-page creation and blocks until the circuit builds). Proven: with a warm circuit the probe reaches `stage=settled` (variants B/D and a warmed nowsecure run); cold, it hangs at `stage=connected`. The watchdog-first refactor makes the probe always emit + exit regardless. Pre-warming the circuit helps but is racy (Tor builds per-destination circuits).
- **Tor does not trigger the managed challenge anyway.** `nowsecure.nl` and `filecrypt.cc` both return **HTTP 200 real pages** through multiple sampled Tor exits (`185.220.100.243`, `194.32.107.14`, `185.220.101.28`, `185.220.101.10`). The `challenge-platform` strings in the body are CF's passive **jsd (JavaScript Detections) telemetry** (`/cdn-cgi/challenge-platform/scripts/jsd/...`), present on every CF page — **not** a managed-challenge interstitial. No `challenges.cloudflare.com` OOPIF ever formed.

**Conclusion:** filecrypt's managed challenge is gated by far more than a flagged IP — specific protected resources (`/Container/<id>.html`) + reputation/behavioural tiers — and is **not reproducible from this harness** via clean IP or Tor. The only deterministic route left to a real CF managed challenge (with `chlPageData`) is a **self-hosted Cloudflare zone with a WAF custom rule action = Managed Challenge** (Free plan; serves the real `cType=managed` interstitial to any visitor incl. Huey's clean IP) — requires a domain on a Cloudflare account.

### Updated scorecard
| # | Claim | Verdict |
|---|-------|---------|
| 1 | `Browser.EachEvent` sees OOPIF attach that `Page.EachEvent` drops | ✅ PROVEN on a real iframe OOPIF (fixture) |
| 3a | document_start injection runs inside the OOPIF | ✅ PROVEN on a real iframe OOPIF (fixture) |
| 3b | capture `action/cData/chlPageData` from the OOPIF child | ✅ PROVEN (all 4 fields, fixture) |
| 2 | CF's *real* managed challenge produces this OOPIF | ⛔ still blocked — needs self-hosted CF Managed Challenge zone or a genuine flagged-production repro |
| 4 | params recoverable from network | ❌ refuted (jsd `oneshot` body is opaque) |

## Reproduce
```
# build probe image on Huey (investigation image must exist first)
docker build -f Dockerfile.probe -t flaresolverr-go:probe .
# local OOPIF fixture — validates the full capture chain incl chlPageData (deterministic)
docker run --rm flaresolverr-go:probe /usr/local/bin/probe -fixture=true -settle 12s

# flagged egress via Tor (note: does NOT trigger filecrypt/nowsecure managed challenge)
docker network create tornet; docker run -d --name tor-proxy --network tornet peterdavehello/tor-socks-proxy
docker run --rm --network tornet flaresolverr-go:probe /usr/local/bin/probe \
  -url https://filecrypt.cc/ -proxy socks5://tor-proxy:9150 -site-per-process=true -settle 30s -maxrun 95s
```

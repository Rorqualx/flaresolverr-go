# Investigation: Gate-2 fingerprint probes (issues #11/#13 root cause)

Experiments run 2026-06-19 against current `main` (f6f106b) on Huey (clean IP,
`flaresolverr-invest` :8195, Chrome 136, HEADLESS=true). Goal: measure what about
*our browser* is detectable, since the #11/#13 wall is gate-2 (automation
fingerprint), and gate-2 lives in our code regardless of IP.

## Method
- **P1 JS surface** — `executeJs` dump of navigator/WebGL/screen/window over `https://example.com`.
- **P2 TLS/HTTP2** — navigate `https://tls.peet.ws/api/all`, capture JA3/JA4/Akamai-H2.
- **P3 automation detector** — scrape `https://bot.sannysoft.com/` pass/fail grid.
- **A/B** — same JS dump on the non-session path (`request.get`) vs the session path (`SolveWithPage`).

## Results

### Ruled OUT (not our tell — stop chasing these)
- **TLS/HTTP2 = genuine Chrome 136.** JA4 `t13d1517h2_8daaf6152771_b6f405a00624`; Akamai H2 `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. Indistinguishable from real Chrome. **This refutes issue #13's own top hypothesis ("improve the TLS/HTTP2 layer").** We drive a real Chromium, so transport is real.
- **Automation/CDP surface clean.** sannysoft passes everything (webdriver, chrome obj, permissions, plugins, all PHANTOM/HEADCHR/SELENIUM/CHR_* checks). `cdpGlobals` empty. go-rod never calls `Runtime.enable` (the puppeteer/playwright leak `rebrowser-patches` fixes) — verified in source. Not our problem.

### Confirmed DEFECTS (in our code, fixable, affect every IP)

**A — Stealth divergence (HIGH).** The primary `request.get`/POST paths apply only
`go-rod/stealth` (library), which spoofs WebGL to the **macOS** string
`Intel Inc.` / `Intel Iris OpenGL Engine` on a **Linux** browser — an OS-layer
inconsistency CF cross-checks. Our superior custom `internal/browser/stealth.go`
(Linux-correct `Google Inc. (Intel)` / `ANGLE (Intel, Intel(R) Iris(TM) Plus
Graphics 655, OpenGL 4.1)`) is wired **only** into the session path
(`SolveWithPage` → `ApplyStealthToPage`, solver.go:2960). A/B proof:
| Path | WebGL renderer |
|---|---|
| `request.get` (go-rod/stealth only) | `Intel Iris OpenGL Engine` (macOS — TELL) |
| session (custom stealth.go) | `ANGLE (Intel, …)` (Linux — correct) |

**B — Impossible screen geometry (HIGH, all paths).** `screen.width/height =
800×600` (headless default) while the viewport is `1920×1080`. A screen smaller
than the window is physically impossible — a top-tier headless tell. Neither
`go-rod/stealth` nor our `stealth.go` overrides `screen.*` (confirmed: go-rod/stealth
patches `outerWidth/Height` but not `screen`; stealth.go patches `screenX/Y` only).

**C — Window-chrome geometry (MEDIUM).** Non-session path has `outerHeight ==
innerHeight` (no browser chrome → headless tell). Custom path adds an offset but
isn't on the main path.

## Solution (implemented)
1. **Wire custom stealth onto GET/POST paths** — call `ApplyStealthToPage` after
   `stealth.Page()` so the Linux-correct WebGL + geometry patches apply to every
   request, not just sessions. Our `getParameter` wrapper registers after
   go-rod/stealth's, so it wins.
2. **Add coherent screen/window geometry override** to `stealth.go`: derive a
   `screen`/`avail*`/`outerWidth/Height` set from the real viewport so
   `inner < outer < avail < screen` always holds (kills B and C) without lying
   about `innerWidth/Height` (which CF can cross-check via media queries).

Re-probe after deploy validates the fixes (see commit).

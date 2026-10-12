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

The sections above record the June 2026 probes. This section describes the
code as it is now; where the two differ, this section is current.

### One page setup for every path

`browser.PreparePage` (internal/browser/page_setup.go) prepares every request
page: stateless GET, stateless POST and session. It applies, in order:

1. **go-rod/stealth**, registered to run at the start of every new document.
2. **`ApplyGate2Corrections`**: the Linux-correct WebGL renderer and a coherent
   `screen`/`avail*`/`outerWidth/Height` set derived from the real viewport, so
   `inner <= outer <= avail <= screen` holds (defects A, B and C) without lying
   about `innerWidth/Height`. Its `getParameter` wrapper registers after
   go-rod/stealth's, so it wins.
3. **Timezone** through CDP (`Emulation.setTimezoneOverride`), when one is set.
4. **User agent** through CDP, with the client hints, `navigator.platform` and
   language list that belong to it (`buildUAOverride`, user_agent.go).
5. **Viewport** 1920x1080.

`navigator.languages` is left as Chrome reports it. go-rod/stealth replaces it
with a fixed `['en-US', 'en']`; the page setup keeps Chrome's own property
across go-rod/stealth and restores it, so it follows the same language list as
the `Accept-Language` header.

The project's own stealth script (`stealthScript` in stealth.go) is no longer
applied to request pages. It is still what the stealth extension loads for the
two-phase reconnect bypass, where Chrome runs without a CDP connection and
go-rod/stealth cannot be injected.

**What was tried first and reverted:** layering the full custom script over
go-rod/stealth on the GET/POST paths. Re-probing bot.sannysoft.com showed it
regressed go-rod/stealth's `navigator.webdriver` and `navigator.plugins`
patches, which is why the corrections are deliberately minimal.

### October 2026 re-probe: the session path

Run on the same host (Chromium 136, linux/amd64, HEADLESS=true) with
`.claude/skills/issue-driven-fix/scripts/probe_template.py --path both`. Before
the single page setup, the session path used the custom script instead of
go-rod/stealth and never set a user agent or viewport:

| Value | Stateless | Session (before) | Both (after) |
|---|---|---|---|
| `navigator.userAgent` and `User-Agent` | Linux, Chrome/136 | **Macintosh, Chrome/114** (go-rod's default device) | Linux, Chrome/136 |
| `Sec-CH-UA` headers | present | **absent** | present |
| window inner size | 1920x1080 | **1280x800** | 1920x1080 |
| `navigator.webdriver` | `false`, on the prototype | **`null`, own property** | `false`, on the prototype |
| `navigator.plugins` | PluginArray of 5 | **plain Array of 3** | PluginArray of 5 |
| `hardwareConcurrency` | 4 (real) | **8** | 4 (real) |
| `devicePixelRatio` | 1 | **1.25**, media query matched 1 | 1 |
| `navigator.connection` | NetworkInformation | **plain Object** | NetworkInformation |
| sannysoft rows failed | none (31 pass) | **"WebDriver (New)", "Plugins is of type PluginArray"** | none (31 pass) |

After the change the fingerprint dump of the two paths is identical apart from
the storage quota (below). nowsecure.nl solved 5 of 5 on each path before and
after. TLS and HTTP/2 were identical on both paths throughout (JA4
`t13d1516h2_8daaf6152771_d8a2da3f94cd`, the Akamai H2 string above).

### User agent override

The override is required, not optional: with no override Chrome sends
`HeadlessChrome/136` in headless mode, and go-rod applies a default device to
every page (the macOS Chrome 114 user agent above, with no client hints).

| Value | Before | Now | Chrome's own |
|---|---|---|---|
| `navigator.platform` | `Linux` | `Linux x86_64` | `Linux x86_64` |
| UA-CH architecture / bitness | `x86_64` / 64 | `x86` / 64 | `x86` / 64 |
| `Sec-CH-UA` | `"Not_A Brand";v="8", "Chromium";v="136", "Google Chrome";v="136"` | `"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"` | `"Not.A/Brand";v="99", "Chromium";v="136"` |
| UA-CH full version | `136.0.0.0` | `136.0.7103.113` | `136.0.7103.113` |
| `Accept-Language` | `en-US,en;q=0.9;q=0.9` | `en-US,en;q=0.9` | `en-US,en;q=0.9` |

The brand list is generated the way Chromium generates it for the user agent's
major version (the greased brand and the order both depend on the version), so
a per-request `userAgent` naming another Chrome version gets that version's
list. "Google Chrome" is kept in the list, as it always was: the user agent
claims Chrome, and that brand is what Chrome of that version sends. The
browser's own list names Chromium only. A user agent that is not Chrome gets no
client hints.

`platformVersion` is a fixed `6.5.0` on Linux; Chrome reports the host kernel
version (`6.8.0` on the test host). Not changed.

### Measured and left alone

- **Hover and pointer media queries.** With `HEADLESS=true`, `(hover: hover)`,
  `(any-hover: hover)`, `(pointer: fine)` and `(any-pointer: fine)` are all
  false on both paths: a desktop browser with no pointing device. go-rod/stealth
  does not cover it. In the image's default mode (`HEADLESS=false`, under Xvfb)
  all four are true. Not patched; run headed if it matters.
- **Storage quota.** `navigator.storage.estimate()` reports about 1.6-2.1 GB in
  the isolated browser contexts every request and session now runs in, and the
  figure differs from one context to the next. In the browser's default
  context it reports 575,898 MB on the test host (60% of the disk), the same
  every time. This is how Chrome treats an off-the-record context, so a page
  can tell it is in one, as it can for a person's incognito window. It was the
  same on both paths. Not patched.
- **Canvas.** Request pages have no canvas patch; repeated reads of an
  untouched canvas are identical. The idempotent canvas noise lives in the
  custom script and so applies only on the reconnect bypass.

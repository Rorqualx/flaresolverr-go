# Cloudflare Capabilities Analysis & FlareSolverr-Go Roadmap

## Executive Summary

This analysis compares Cloudflare's current (2025-2026) anti-bot detection capabilities against FlareSolverr-Go's implementation, identifying gaps and creating a **realistic, feasibility-assessed roadmap** to improve FlareSolverr-Go's evasion capabilities.

**Strategic Vision**: Focus on what's actually achievable with browser automation (Rod/Chrome DevTools Protocol) architecture, prioritizing high-impact improvements that are technically feasible.

> **Last Updated**: February 2026
> **Architecture**: Go + Rod (Chrome DevTools Protocol)

---

## Part 1: Cloudflare's Current Detection Arsenal (2025-2026)

### Detection Layers

| Layer | Technique | Description | Can We Counter? |
|-------|-----------|-------------|-----------------|
| **Network** | IP Reputation | Historical data on IP addresses, ASN scoring | ⚠️ Proxy rotation only |
| **Network** | TLS Fingerprinting (JA3/JA4) | Analyzes TLS handshake patterns unique to browsers | ❌ Chrome controls this |
| **Network** | HTTP/2 Fingerprinting | Header order, pseudo-header patterns, SETTINGS frame | ❌ Chrome controls this |
| **Browser** | JavaScript Challenges | Proof-of-work and environment verification | ✅ Stealth scripts |
| **Browser** | Turnstile CAPTCHA | Non-interactive, invisible, or interactive challenges | ✅ Native + solver fallback |
| **Browser** | Browser Fingerprinting | Canvas, WebGL, AudioContext, fonts | ✅ JS injection |
| **Behavioral** | Mouse/Keyboard Patterns | Detects robotic movement patterns | ✅ Humanization |
| **Behavioral** | Navigation Timing | Request rate, sequence, dwell time | ✅ Randomization |
| **ML** | Per-Customer Models | Site-specific behavioral patterns learned over time | ⚠️ Per-domain profiles |

### Turnstile Modes (Current)

1. **Non-Interactive (Invisible)**: Background fingerprinting + behavioral analysis
2. **Invisible (Brief Check)**: 1-2 second "Verifying you are human" message
3. **Interactive**: Checkbox click required when trust score is low

---

## Part 2: FlareSolverr-Go Current Implementation

### What's Currently Implemented

| Category | Feature | Status | Files |
|----------|---------|--------|-------|
| **Webdriver** | navigator.webdriver masking | ✅ Active | `browser/stealth.go` |
| **Plugins** | Plugin array spoofing | ✅ Active | `browser/stealth.go` |
| **WebGL** | GPU vendor/renderer spoofing | ✅ Active | `browser/stealth.go` |
| **Chrome** | window.chrome mock | ✅ Active | `browser/stealth.go` |
| **Functions** | toString leak prevention | ✅ Active | `browser/stealth.go` |
| **Display** | Xvfb virtual display | ✅ Active | `browser/pool.go` |
| **WebRTC** | IP leak prevention | ✅ Active | `browser/pool.go` |
| **Proxy** | Per-request proxy support | ✅ Active | `browser/proxy.go` |
| **UA** | User-Agent + Client Hints | ✅ Active | `browser/stealth.go` |
| **Hardware** | Concurrency/memory spoofing | ✅ Active | `browser/stealth.go` |
| **Challenge** | JS challenge detection | ✅ Active | `solver/solver.go` |
| **Challenge** | Turnstile 3-pronged solve | ✅ Active | `solver/solver.go` |
| **Challenge** | Access denied detection | ✅ Active | `solver/solver.go` |
| **Selectors** | YAML-configurable patterns | ✅ Active | `selectors/selectors.yaml` |
| **Security** | SSRF protection | ✅ Active | `security/url_validator.go` |
| **Security** | Rate limiting | ✅ Active | `middleware/ratelimit.go` |
| **Stats** | Domain statistics tracking | ✅ Active | `stats/` |
| **Sessions** | TTL-based session management | ✅ Active | `session/` |

---

## Part 3: Gap Analysis (Feasibility-Assessed)

### Architecture Constraint

> **Critical Understanding**: FlareSolverr-Go uses a real Chrome browser via Rod (Chrome DevTools Protocol). This means:
> - **Chrome controls the network layer** - TLS handshakes, HTTP/2 negotiation, etc.
> - **We can only inject JavaScript** - Browser fingerprint spoofing is feasible
> - **We can control mouse/keyboard** - Behavioral simulation is feasible
> - **We cannot modify Chrome's network stack** - TLS/HTTP2 fingerprinting is NOT addressable

### Gaps by Feasibility

#### ✅ FEASIBLE - JavaScript Injection (High Priority)

| Gap | Effort | Impact | Implementation |
|-----|--------|--------|----------------|
| **Canvas Fingerprinting** | 1-2 days | HIGH | Inject noise into `getImageData()`, `toDataURL()` |
| **AudioContext Fingerprinting** | 1 day | MEDIUM | Override `createOscillator`, add processing noise |
| **Font Enumeration** | 0.5 days | MEDIUM | Limit `document.fonts` API responses |
| **Timezone Consistency** | 1 day | MEDIUM | Override `Date`, `Intl.DateTimeFormat` based on proxy |
| **Speech Synthesis** | 0.5 days | LOW | Return consistent fake voice list |
| **Battery API** | 0.5 days | LOW | Mock `navigator.getBattery()` (deprecated anyway) |

#### ✅ FEASIBLE - Rod API (High Priority)

| Gap | Effort | Impact | Implementation |
|-----|--------|--------|----------------|
| **Bezier Mouse Movement** | 2-3 days | HIGH | Use `page.Mouse.Move()` with Bezier curves |
| **Click Timing Randomization** | 0.5 days | MEDIUM | Random delays before/after clicks |
| **Scroll Simulation** | 1 day | MEDIUM | `page.Mouse.Scroll()` with natural patterns |
| **Keyboard Timing** | 1 day | LOW | Variable delays between keystrokes |
| **Random Polling Intervals** | 0.5 days | MEDIUM | Replace fixed 1s with 0.8-1.5s random |

#### ✅ FEASIBLE - External APIs (Medium Priority)

| Gap | Effort | Impact | Implementation |
|-----|--------|--------|----------------|
| **2Captcha Integration** | 1-2 days | HIGH | HTTP API for Turnstile token solving |
| **CapSolver Integration** | 1-2 days | HIGH | Alternative solver service |
| **Solver Fallback Chain** | 1 day | HIGH | Native → 2Captcha → CapSolver |

#### ⚠️ MODERATE EFFORT (Lower Priority)

| Gap | Effort | Impact | Notes |
|-----|--------|--------|-------|
| **Hot-reload Selectors** | 2-3 days | MEDIUM | `fsnotify` or periodic HTTP fetch |
| **Per-domain Profiles** | 3-5 days | MEDIUM | Extend existing `internal/stats/` |
| **WebGL Shader Noise** | 3-5 days | LOW | Complex shader interception |

#### ❌ NOT FEASIBLE (Architecture Mismatch)

| Gap | Why Not Feasible | Alternative |
|-----|------------------|-------------|
| **TLS Fingerprinting (JA3/JA4)** | Chrome handles TLS, not Go code. uTLS only works for Go HTTP clients. | Use real Chrome (already doing this) |
| **HTTP/2 Fingerprinting** | Chrome controls HTTP/2 SETTINGS frames | None - Chrome's fingerprint is legitimate |
| **JA4 Spoofing** | Same as above - network layer is Chrome's domain | None |

> **Note**: The original roadmap incorrectly proposed uTLS integration. uTLS is for **headless HTTP clients** (colly, resty), not browser automation. When using a real browser, Cloudflare sees Chrome's actual TLS fingerprint, which is already legitimate.

#### ❌ NOT WORTH THE EFFORT

| Gap | Effort | Why Skip |
|-----|--------|----------|
| **Firefox Support** | 2-3 weeks | Doubles maintenance, Rod is Chrome-only, marginal benefit |
| **ML Challenge Prediction** | Weeks+ | Training data unavailable, over-engineered |
| **Distributed Testing Infra** | Weeks | DevOps project, not a code feature |

---

## Part 4: Strategic Approach (Revised)

### Focus Areas

```
High Impact + Feasible          Medium Impact + Feasible       Skip
─────────────────────────       ────────────────────────       ────
• Canvas/Audio fingerprints     • Hot-reload selectors         • TLS fingerprinting
• Bezier mouse movement         • Per-domain profiles          • HTTP/2 fingerprinting
• CAPTCHA solver fallback       • WebGL shader noise           • Firefox support
• Random timing patterns        • Extended stats               • ML prediction
```

### Key Technical Decisions (Updated)

| Decision | Rationale |
|----------|-----------|
| ~~Use uTLS for TLS spoofing~~ | ❌ **REMOVED** - Not applicable to browser automation |
| **Bezier curves** for mouse | ✅ Matches human neuromotor patterns, Rod supports it |
| **External solver fallback** | ✅ Insurance for hard Turnstile challenges |
| **Per-domain profiles** | ✅ Counter per-customer ML models, extend existing stats |
| **Hot-reload selectors** | ✅ Adapt without downtime |

---

## Part 5: Revised Phased Roadmap (8-Week Timeline)

### PHASE 1: BROWSER FINGERPRINT HARDENING (Weeks 1-2) ✅ COMPLETE
*Goal: Pass fingerprint detection tests*

#### Week 1: Canvas & Audio Spoofing

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Canvas fingerprint noise injection | P0 | 1.5 days | `browser/stealth.go` | ⏳ Pending |
| AudioContext fingerprint spoofing | P1 | 1 day | `browser/stealth.go` | ✅ Done (v0.5.0) |
| Font enumeration limiting | P2 | 0.5 days | `browser/stealth.go` | ✅ Done |

#### Week 2: Consistency & Minor Fingerprints

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Timezone/geolocation consistency | P1 | 1 day | `browser/stealth.go` | ✅ Done |
| Speech synthesis voice list | P2 | 0.5 days | `browser/stealth.go` | ✅ Done |
| Battery API mock | P3 | 0.5 days | `browser/stealth.go` | ✅ Done |

**Deliverable**: Pass [CreepJS](https://abrahamjuliot.github.io/creepjs/) and [BrowserScan](https://browserscan.net/) with minimal detection flags

---

### PHASE 2: BEHAVIORAL SIMULATION (Weeks 3-4) ✅ COMPLETE
*Goal: Human-like interaction patterns*

#### Week 3: Mouse Movement

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Bezier curve mouse movement library | P0 | 2 days | `internal/humanize/mouse.go` | ✅ Done |
| Integrate with Turnstile clicking | P0 | 1 day | `solver/solver.go` | ✅ Done |
| Click position randomization | P1 | 0.5 days | `humanize/mouse.go` | ✅ Done |

#### Week 4: Timing Randomization

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Random polling intervals (0.8-1.5s) | P0 | 0.5 days | `solver/solver.go` | ✅ Done |
| Pre-click hover delay | P1 | 0.5 days | `solver/solver.go` | ✅ Done |
| Post-action dwell time | P2 | 0.5 days | `solver/solver.go` | ✅ Done |
| Scroll behavior before actions | P2 | 1 day | `humanize/scroll.go` | ✅ Done |

**Deliverable**: Natural-looking mouse trails in browser recordings

---

### PHASE 3: CAPTCHA RESILIENCE (Weeks 5-6) ✅ COMPLETE
*Goal: 99%+ Turnstile success rate*

#### Week 5: External Solver Integration

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Solver interface definition | P0 | 0.5 days | `internal/captcha/solver.go` | ✅ Done |
| 2Captcha Turnstile integration | P0 | 1.5 days | `internal/captcha/twocaptcha.go` | ✅ Done |
| CapSolver integration | P1 | 1 day | `internal/captcha/capsolver.go` | ✅ Done |

**API Flow**:
```
1. Extract Turnstile sitekey from page (captcha/extraction.go)
2. POST to solver API with sitekey + URL
3. Poll for token (typically 10-30 seconds)
4. Inject token via turnstileCallback (captcha/injection.go)
5. Verify challenge resolved
```

#### Week 6: Fallback Chain

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Automatic fallback after N native failures | P0 | 1 day | `solver/solver.go` | ✅ Done |
| Token injection mechanism | P0 | 1 day | `captcha/injection.go` | ✅ Done |
| Solver selection configuration | P1 | 0.5 days | `config/config.go` | ✅ Done |
| Cost/usage metrics | P2 | 0.5 days | `captcha/metrics.go` | ✅ Done |

**Configuration** (via environment variables):
```bash
CAPTCHA_NATIVE_ATTEMPTS=3      # Try native solving first
CAPTCHA_FALLBACK_ENABLED=true
TWOCAPTCHA_API_KEY=your-key
CAPSOLVER_API_KEY=your-key
CAPTCHA_PRIMARY_PROVIDER=2captcha
```

**Deliverable**: Configurable solver fallback with metrics

---

### PHASE 4: ADAPTIVE INTELLIGENCE (Weeks 7-8) ✅ COMPLETE
*Goal: Self-tuning per-domain behavior*

#### Week 7: Hot-Reload & Dynamic Config

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| File watcher for selectors.yaml | P1 | 1 day | `selectors/manager.go` | ✅ Done |
| Reload without restart | P1 | 1 day | `selectors/manager.go` | ✅ Done |
| Remote selector fetch (optional) | P2 | 1 day | `internal/updates/remote.go` | ⏳ Future |

#### Week 8: Per-Domain Profiling

| Task | Priority | Effort | Files | Status |
|------|----------|--------|-------|--------|
| Extend stats with Turnstile method tracking | P1 | 1 day | `stats/domain_stats.go` | ✅ Done |
| Adaptive method ordering based on success | P1 | 1 day | `stats/domain_stats.go` | ✅ Done |
| Domain-specific solver preferences | P2 | 1 day | `stats/domain_stats.go` | ✅ Done |

**Deliverable**: System learns optimal settings per target domain

---

## Part 6: What We're NOT Doing (And Why)

### TLS/HTTP2 Fingerprinting - Architecture Mismatch

The original roadmap proposed integrating uTLS for JA3/JA4 spoofing. This was incorrect because:

1. **FlareSolverr uses a real browser** - Chrome handles all network operations
2. **uTLS replaces Go's TLS stack** - Useful for `http.Client`, not browser automation
3. **Chrome's TLS fingerprint is already legitimate** - It's actual Chrome!

When Cloudflare checks TLS fingerprints against FlareSolverr traffic, they see Chrome's real fingerprint because we're using real Chrome. This is actually an advantage.

### Firefox Support - Not Worth It

| Factor | Assessment |
|--------|------------|
| Effort | 2-3 weeks minimum |
| Benefit | Marginal - Chrome fingerprint is already valid |
| Maintenance | Doubles ongoing work |
| Rod compatibility | Would need playwright-go or custom CDP |

### ML-Based Prediction - Over-Engineered

Challenge prediction via ML would require:
- Training data from diverse Cloudflare-protected sites
- Continuous model updates as Cloudflare changes
- Significant infrastructure for inference

The reactive approach (detect → solve → learn) is simpler and more maintainable.

---

## Part 7: Success Metrics (Realistic)

### Phase 1-2 (Fingerprint + Behavioral) ✅
- [x] Battery API, Speech Synthesis, Font Enumeration, Timezone consistency implemented
- [x] Mouse movement with Bezier curves implemented (`humanize/mouse.go`)
- [x] Randomized timing patterns implemented (`humanize/timing.go`)
- [ ] CreepJS detection flags: <3 (needs testing)
- [ ] BrowserScan bot probability: <10% (needs testing)

### Phase 3-4 (CAPTCHA + Adaptive) ✅
- [x] 2Captcha integration (`captcha/twocaptcha.go`)
- [x] CapSolver integration (`captcha/capsolver.go`)
- [x] Solver fallback chain with metrics (`captcha/solver.go`, `captcha/metrics.go`)
- [x] Per-domain Turnstile method tracking (`stats/domain_stats.go`)
- [x] Hot-reload selectors (`selectors/manager.go`)
- [ ] Turnstile solve rate: >99% (needs real-world testing)
- [ ] Average solve time: <8 seconds (needs benchmarking)

### NOT Measuring (Removed)
- ~~JA3/JA4 fingerprint matches Chrome~~ (Already true - we use real Chrome)
- ~~Zero-day evasion capability~~ (Unrealistic goal)

---

## Part 8: Risk Assessment (Updated)

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Cloudflare updates break selectors | High | Medium | Hot-reload selectors, community updates |
| Behavioral analysis defeats patterns | Medium | Medium | Continuous humanization improvements |
| CAPTCHA solver services go down | Low | High | Multiple solver fallbacks |
| Canvas noise detected | Medium | Low | Randomize noise patterns |
| Per-customer ML defeats us on specific sites | Medium | Medium | Per-domain profile adaptation |

### Risks Removed
- ~~uTLS fingerprints become detected~~ - Not using uTLS
- ~~HTTP/2 fingerprinting~~ - Chrome handles this, not our concern

---

## Part 9: Implementation Priority Summary

### Must Have (Weeks 1-6)
1. ⏳ Canvas fingerprint spoofing (pending)
2. ✅ AudioContext spoofing (v0.5.0)
3. ✅ Bezier curve mouse movement (`humanize/mouse.go`)
4. ✅ Random timing patterns (`humanize/timing.go`)
5. ✅ 2Captcha/CapSolver integration (`captcha/`)
6. ✅ Solver fallback chain (`captcha/solver.go`)

### Should Have (Weeks 7-8)
7. ✅ Hot-reload selectors (`selectors/manager.go`)
8. ✅ Per-domain profiling (`stats/domain_stats.go`)
9. ✅ Timezone consistency (`browser/stealth.go`)

### Nice to Have (Future)
10. ⏳ WebGL shader noise
11. ⏳ Remote selector updates
12. ⏳ Extended keyboard humanization

---

## Appendix A: Reference Implementations

### Canvas Spoofing
- [puppeteer-extra-plugin-stealth](https://github.com/AtoMiq/puppeteer-extra-plugin-stealth) - `evasions/canvas.fp.js`
- [playwright-stealth](https://github.com/nicjac/playwright_stealth)

### Bezier Mouse Movement
- [ghost-cursor](https://github.com/Xetera/ghost-cursor) - TypeScript, easily portable
- [bezier-easing](https://github.com/gre/bezier-easing) - Math reference

### CAPTCHA Solver APIs
- [2Captcha Turnstile Docs](https://2captcha.com/2captcha-api#turnstile)
- [CapSolver Turnstile Docs](https://docs.capsolver.com/guide/captcha/cloudflare_turnstile.html)

---

## Appendix B: Removed Sections

The following sections from the original roadmap have been removed as not applicable:

1. **Part 5: TLS Fingerprinting Options** - uTLS, CycleTLS, spoofed-round-tripper analysis removed. These tools are for Go HTTP clients, not browser automation.

2. **Week 1: Network Layer Hardening** - All TLS/HTTP2 tasks removed.

3. **Phase 5: Offensive Capabilities** - Firefox support, ML prediction, distributed testing removed as over-scoped.

---

## Sources

- [ZenRows - Bypass Cloudflare 2026](https://www.zenrows.com/blog/bypass-cloudflare)
- [Scrapfly - Bypass Cloudflare 2026](https://scrapfly.io/blog/posts/how-to-bypass-cloudflare-anti-scraping)
- [CapSolver - Solve Cloudflare 2026](https://www.capsolver.com/blog/Cloudflare/solve-cloudflare-in-2026)
- [puppeteer-extra-plugin-stealth](https://github.com/berstend/puppeteer-extra/tree/master/packages/puppeteer-extra-plugin-stealth)
- [ghost-cursor](https://github.com/Xetera/ghost-cursor)
- [Cloudflare Bot Management](https://developers.cloudflare.com/bots/)

---

*Last updated: February 7, 2026*
*Architecture: Go + Rod (Chrome DevTools Protocol)*

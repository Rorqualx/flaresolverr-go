---
name: issue-driven-fix
description: End-to-end loop for resolving GitHub issues empirically — review/triage issues, root-cause with codebase analysis, design and run live probes/experiments, analyze data, design a minimal evidence-driven solution, implement with tests, verify locally + re-probe live for regressions, deploy to the test harness, ship via branch→CI→merge→release, and report back on the issue. Use when asked to "review/work the issues", "investigate and fix", "run the workflow on issue N", or for any anti-bot/fingerprint/Cloudflare debugging that needs a real browser. Anchors on the Huey deploy harness for live validation.
---

# Issue-Driven Fix Loop

A disciplined, **empirical** loop for turning GitHub issues into shipped, validated fixes. The governing principle: **probe, don't guess — and re-probe after fixing.** Most wasted effort in this repo's issue history came from plausible-but-wrong hypotheses that a single live measurement would have refuted.

Follow the phases in order. Skip a phase only when it's genuinely N/A, and say so.

## Project anchors (verify before relying on)
- **CLAUDE.md** (root) defines coding standards — follow them exactly (package layout, error wrapping, `defer` cleanup, table-driven tests, no business logic in handlers, no hardcoded selectors).
- **Code search:** use `ast-grep --pattern '...'` for code patterns, `rg`/`grep` only for non-code text.
- **Live harness:** Huey = `192.168.50.185`, user `joe` (key in `~/.ssh/config`). Production `flaresolverr` on :8191 — **do not disturb**. Test container `flaresolverr-invest` on :8195. See the memory `project-huey-deploy-harness` for the exact build/deploy pattern. Local macOS can't drive a real browser well — use Huey for anything browser/fingerprint/Cloudflare.
- **gh CLI** is authorized for issues/PRs/releases/runs.

---

## Phase 1 — Review & triage issues
```bash
gh issue list --state open --limit 30
gh issue view <N>; gh issue view <N> --comments
```
- Read the **full** thread including comments — prior commenters often already root-caused or refuted a path. Distinguish a **confirmed code bug** from an **environmental/external wall** (they need different handling; conflating them sends you down the wrong path).
- Triage outcome per issue: close as not-planned (with a documented reason) for external/won't-fix; keep open for actionable work; split an issue into the part that's fixable now vs the residual.
- When you post triage, **quote the evidence** and name what's ruled out.

## Phase 2 — Root-cause analysis (codebase)
- Map the relevant code with `ast-grep`/Read. Trace the actual call paths (e.g. which stealth/solve path a request type takes — they often diverge).
- Form **explicit competing hypotheses** and, for each, the decisive check that would confirm or refute it.
- Build a model before measuring (e.g. "two stacked gates: IP tier vs fingerprint"). A wrong fix to the wrong gate looks busy and helps no one.
- Verify framework/library behavior against the actual vendored source (e.g. does go-rod call `Runtime.enable`?), not memory or blog lore.

## Phase 3 — Design & run probes (live experiments)
This is the differentiator. Design experiments that **isolate one variable each** and run them against the live harness.
- Reuse `scripts/probe_template.py` (bundled with this skill) as the driver. It POSTs `request.get` with `executeJs` to dump structured JSON from a real page, and reads raw bodies (e.g. `https://tls.peet.ws/api/all`) for transport fingerprints.
- Build/deploy current code to `flaresolverr-invest` first so you measure **shipped** behavior, not a stale image:
  ```bash
  tar --exclude=.git -czf /tmp/fsg-invest.tgz -C <repo> .
  scp -q /tmp/fsg-invest.tgz joe@192.168.50.185:/tmp/
  ssh joe@192.168.50.185 'cd ~/flaresolverr-investigation && rm -rf ./* && \
    tar -xzf /tmp/fsg-invest.tgz -C . && docker build -q -t flaresolverr-go:investigation . && \
    docker rm -f flaresolverr-invest 2>/dev/null; \
    docker run -d --name flaresolverr-invest -p 8195:8191 -e LOG_LEVEL=debug -e RATE_LIMIT_ENABLED=false \
      flaresolverr-go:investigation'
  ```
- Use **A/B probes** to localize a defect (e.g. session path vs non-session path revealed which stealth layer shipped).
- Pick targets that reliably exhibit the phenomenon (e.g. `nowsecure.nl` reliably issues `cf_clearance`; a site that passes natively from a clean IP proves nothing about a stuck challenge).

## Phase 4 — Analyze the data
- State what each probe **confirmed** and **ruled out**. Ruling things out is as valuable as finding the bug — it stops the whole thread chasing a dead vector.
- Reduce to concrete, named defects with evidence (file:line + measured value), ranked by signal strength.

## Phase 5 — Design the solution
- **Minimal and surgical.** Prefer the smallest change that fixes the measured defect over a broad rewrite. (Layering an entire stealth script caused regressions; a 2-fix targeted patch didn't.)
- Respect couplings (e.g. a cache keyed by an identity must move in lockstep with whatever sets that identity).
- Be honest about the **value ceiling**: if a fix can't help the reported case (gated by something else), say so and pick the path with real, testable payoff.

## Phase 6 — Implement
- Follow CLAUDE.md. Accept interfaces / return structs, context first, `defer` every acquire, bound every buffer/map, sentinel/wrapped errors, no naked goroutines.
- Add table-driven unit tests next to the code for every new component. Make time/randomness injectable for deterministic tests.

## Phase 7 — Verify (local + live re-probe)
```bash
go build ./... && go vet ./... && go test -short ./internal/<pkg>/...
```
- **Then re-deploy and re-probe.** Confirm the target metric flipped AND run a **regression probe** (e.g. sannysoft all-pass) — a fix on the hot path can silently break an adjacent property. Empirical re-validation has caught real regressions a green build did not.
- For config/CI changes, validate with the real tool, not assumption (e.g. `goreleaser check`, install the exact version CI floats to).

## Phase 8 — Deploy / end-to-end
- Run a real end-to-end action through the harness (e.g. an actual CF solve) to confirm the change didn't break the happy path. Capture timing/cookies/logs as evidence.
- Tear down any scratch infra you stood up (test proxies, containers).

## Phase 9 — Ship
- Branch from `main` (never commit straight to default): `git checkout -b <type>/<slug>`.
- Commit with a body explaining the measured finding + fix; end with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- Push, **watch CI to green** (`gh run watch <id> --exit-status`), then merge (`--no-ff` to `main`), push `main`, delete the branch (local + remote).
- For a release: bump CHANGELOG `[Unreleased]`→`[x.y.z]`, tag `vX.Y.Z` (semver: features→minor), push the tag, and watch the Release + Docker workflows. Verify the GitHub release assets and Docker tags exist.

## Phase 10 — Report on the issue
- Post a structured comment: what was **ruled out** (with the data), what was **fixed** (with validation evidence), **honest scope** (what it does and doesn't do), and what residual remains.
- Tag thread participants. Ask for the one data point you can't generate (e.g. "test with a residential `PROXY_LIST`").
- Update memory (`MEMORY.md` + a `project-*` file) with non-obvious findings and ruled-out vectors so the next session doesn't re-investigate.

---

## Anti-patterns (seen in this repo's history)
- Shipping an anti-bot change without a live repro/validation — the class of change that most needs it.
- "Improve the TLS layer" / "patch the Runtime.enable leak" cargo-culted from blogs without checking they apply (they didn't here — measured).
- A green `go build` treated as proof a fingerprint/behavioral change works — it isn't; re-probe.
- Broad fixes that regress adjacent properties; prefer surgical.
- Over-claiming in issue comments; state the value ceiling plainly.

#!/usr/bin/env python3
"""Live probe driver for flaresolverr-go (issue-driven-fix skill).

Drives a container's /v1 API to collect structured evidence from a real
browser, on BOTH request paths (they set pages up differently, so measure both):

  --path stateless   plain request.get
  --path session     sessions.create -> request.get with the session -> destroy

Probes:
  jsfp     wide JS-visible fingerprint dump (sync + async values)
  sanny    every bot.sannysoft.com row as {name, class, value}
  headers  request headers as the server saw them (httpbin.org/headers)
  tls      JA3/JA4 + HTTP2 fingerprint (tls.peet.ws)
  clear    nowsecure.nl solve (cf_clearance issued?), repeat with --runs N
  quota    navigator.storage.estimate() (incognito-context tell check)

Usage:
    python3 probe_template.py jsfp --base http://192.168.50.185:8195 --path session
    python3 probe_template.py all  --base http://192.168.50.185:8195 --path both
    python3 probe_template.py diff --base A --base2 B --path both   # jsfp+sanny A vs B

executeJs runs through rod's Page.Eval, which awaits a returned promise: use
`return somePromise.then(...)`; the `await` keyword is a syntax error there.

Targets that reliably exhibit a CF challenge / issue cf_clearance:
  https://nowsecure.nl/            (embedded Turnstile widget + clearance)
  https://tls.peet.ws/api/all      (JA3/JA4 + Akamai HTTP2 fingerprint, JSON body)
  https://bot.sannysoft.com/       (automation/headless detector grid)
A site that passes natively from a clean IP proves nothing about a stuck challenge.
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

DEFAULT_BASE = "http://192.168.50.185:8195"  # flaresolverr-invest on Huey

# Wide fingerprint dump. Must `return` a string or a promise of one.
FP_JS = r"""
const o = {};
o.ua = navigator.userAgent;
o.webdriver = navigator.webdriver;
o.webdriverOwn = Object.getOwnPropertyNames(navigator).includes('webdriver');
o.webdriverProto = 'webdriver' in Navigator.prototype;
o.platform = navigator.platform;
o.language = navigator.language;
o.languages = navigator.languages;
o.hardwareConcurrency = navigator.hardwareConcurrency;
o.deviceMemory = navigator.deviceMemory;
o.maxTouchPoints = navigator.maxTouchPoints;
o.plugins = Array.prototype.map.call(navigator.plugins, p => p.name);
o.pluginsIsPluginArray = navigator.plugins instanceof PluginArray;
o.pluginsToString = Object.prototype.toString.call(navigator.plugins);
o.mimeTypes = navigator.mimeTypes.length;
o.chrome = {exists: !!window.chrome, runtime: !!(window.chrome && window.chrome.runtime)};
o.cdpGlobals = Object.keys(window).filter(k => /cdc_|_phantom|__nightmare|domAutomation|__webdriver|__selenium|__stealth/.test(k));
o.screen = {w: screen.width, h: screen.height, aw: screen.availWidth, ah: screen.availHeight, depth: screen.colorDepth};
o.win = {ow: window.outerWidth, iw: window.innerWidth, oh: window.outerHeight, ih: window.innerHeight};
o.dpr = window.devicePixelRatio;
o.dprMedia = [1, 1.25, 1.5, 2].filter(r => matchMedia('(resolution: ' + r + 'dppx)').matches);
o.hover = matchMedia('(hover: hover)').matches;
o.pointerFine = matchMedia('(pointer: fine)').matches;
o.connection = navigator.connection ? {type: Object.prototype.toString.call(navigator.connection), rtt: navigator.connection.rtt, eff: navigator.connection.effectiveType} : null;
o.rtc = typeof RTCPeerConnection;
o.tz = Intl.DateTimeFormat().resolvedOptions().timeZone + ' ' + new Date().getTimezoneOffset();
o.notification = (typeof Notification !== 'undefined') ? Notification.permission : 'n/a';
try {
  const c = document.createElement('canvas');
  const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
  const d = gl.getExtension('WEBGL_debug_renderer_info');
  o.webgl = {vendor: gl.getParameter(d.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(d.UNMASKED_RENDERER_WEBGL)};
} catch (e) { o.webgl = 'ERR:' + e.message; }
try {
  const c = document.createElement('canvas'); c.width = 120; c.height = 30;
  const x = c.getContext('2d'); x.fillStyle = '#f60'; x.fillRect(2, 2, 60, 20); x.fillStyle = '#069'; x.fillText('probe', 4, 26);
  const a = c.toDataURL(), b = c.toDataURL();
  o.canvasStable = a === b;
} catch (e) { o.canvasStable = 'ERR:' + e.message; }
const uad = navigator.userAgentData;
o.uaData = uad ? {brands: uad.brands, mobile: uad.mobile, platform: uad.platform} : null;
const hi = uad ? uad.getHighEntropyValues(['architecture', 'bitness', 'platformVersion', 'uaFullVersion', 'fullVersionList', 'model', 'wow64']) : Promise.resolve(null);
const quota = (navigator.storage && navigator.storage.estimate) ? navigator.storage.estimate() : Promise.resolve(null);
return Promise.all([hi, quota]).then(([h, q]) => {
  o.uaHigh = h;
  o.quotaMB = q ? Math.round(q.quota / 1048576) : null;
  return JSON.stringify(o);
});
"""

# Every sannysoft row: [name, class of the result cell, value text].
SANNY_JS = r"""
const rows = [];
document.querySelectorAll('tr').forEach(tr => {
  const cells = tr.cells;
  if (!cells || cells.length < 2) return;
  const res = tr.querySelector('td.passed, td.failed, td.warn') || cells[cells.length - 1];
  const cls = (res.className || '').replace('result', '').trim() || 'none';
  rows.push([cells[0].innerText.trim().replace(/\s+/g, ' ').slice(0, 48), cls, res.innerText.trim().replace(/\s+/g, ' ').slice(0, 70)]);
});
return JSON.stringify(rows);
"""

QUOTA_JS = "return navigator.storage.estimate().then(e => JSON.stringify({quotaMB: Math.round(e.quota/1048576), usage: e.usage}));"


class Client:
    def __init__(self, base, path):
        self.base = base.rstrip("/")
        self.path = path
        self.n = 0

    def call(self, body, t=150):
        req = urllib.request.Request(self.base + "/v1", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            return json.loads(urllib.request.urlopen(req, timeout=t).read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())

    def get(self, url, execjs=None, raw=False, timeout=60000, **extra):
        """request.get on the configured path. A session path uses a fresh session."""
        body = {"cmd": "request.get", "url": url, "maxTimeout": timeout, **extra}
        if execjs:
            body["executeJs"] = execjs
        if raw:
            body["returnRawHtml"] = True
        sid = None
        if self.path == "session":
            self.n += 1
            sid = "probe-%d-%04d-padding0000" % (int(time.time()), self.n)
            created = self.call({"cmd": "sessions.create", "session": sid})
            if created.get("status") != "ok":
                return {"status": "error", "message": "sessions.create: " + str(created.get("message"))}
            body["session"] = sid
        t0 = time.time()
        try:
            out = self.call(body, t=(timeout / 1000) + 90)
        except Exception as e:  # noqa: BLE001
            out = {"status": "CLIENT-ERR", "message": repr(e)}
        finally:
            if sid:
                self.call({"cmd": "sessions.destroy", "session": sid})
        out["_elapsed"] = round(time.time() - t0, 1)
        return out


def js_result(out):
    val = (out.get("solution") or {}).get("executeJsResult")
    if val is None:
        return {"_error": out.get("message")}
    try:
        return json.loads(val)
    except ValueError:
        return {"_raw": val}


def p_jsfp(c):
    out = c.get("https://example.com/", FP_JS)
    res = js_result(out)
    if isinstance(res, dict):
        res["_resultUA"] = (out.get("solution") or {}).get("userAgent")
    return res


def p_sanny(c):
    rows = js_result(c.get("https://bot.sannysoft.com/", SANNY_JS))
    if not isinstance(rows, list):
        return rows
    return {"bad": [r for r in rows if r[1] in ("failed", "warn")],
            "counts": {k: sum(1 for r in rows if r[1] == k) for k in ("passed", "failed", "warn")},
            "rows": rows}


def p_headers(c):
    out = c.get("https://httpbin.org/headers")
    body = re.sub(r"<[^>]+>", "", (out.get("solution") or {}).get("response") or "")
    try:
        hdrs = json.loads(body)["headers"]
    except (ValueError, KeyError):
        return {"_error": out.get("message"), "_body": body[:200]}
    keep = ("User-Agent", "Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Mobile",
            "Sec-Ch-Ua-Arch", "Sec-Ch-Ua-Bitness", "Sec-Ch-Ua-Full-Version-List", "Accept-Encoding")
    return {k: hdrs.get(k) for k in keep if k in hdrs}


def p_tls(c):
    out = c.get("https://tls.peet.ws/api/all")
    body = re.sub(r"<[^>]+>", "", (out.get("solution") or {}).get("response") or "")
    try:
        d = json.loads(body)
    except ValueError:
        return {"_error": out.get("message"), "_body": body[:200]}
    return {"ja4": (d.get("tls") or {}).get("ja4"), "h2": (d.get("http2") or {}).get("akamai_fingerprint"),
            "http_version": d.get("http_version"), "ua": d.get("user_agent")}


def p_clear(c, runs=1):
    res = []
    for _ in range(runs):
        out = c.get("https://nowsecure.nl/")
        sol = out.get("solution") or {}
        res.append({"status": out.get("status"), "http": sol.get("status"),
                    "cf_clearance": any(k.get("name") == "cf_clearance" for k in sol.get("cookies") or []),
                    "elapsed": out.get("_elapsed"), "msg": (out.get("message") or "")[:60]})
    return res


def p_quota(c):
    return js_result(c.get("https://example.com/", QUOTA_JS))


PROBES = {"jsfp": p_jsfp, "sanny": p_sanny, "headers": p_headers, "tls": p_tls, "clear": p_clear, "quota": p_quota}


def flat(d, prefix=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(flat(v, prefix + str(k) + "."))
    else:
        out[prefix[:-1]] = json.dumps(d, sort_keys=True)
    return out


def diff(a, b):
    fa, fb = flat(a), flat(b)
    return {k: [fa.get(k), fb.get(k)] for k in sorted(set(fa) | set(fb)) if fa.get(k) != fb.get(k)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", nargs="?", default="all", help="probe name, 'all', or 'diff'")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--base2", help="second server for 'diff'")
    ap.add_argument("--path", default="stateless", choices=["stateless", "session", "both"])
    ap.add_argument("--runs", type=int, default=1, help="repeat count for 'clear'")
    ap.add_argument("--rows", action="store_true", help="include every sannysoft row")
    args = ap.parse_args()

    paths = ["stateless", "session"] if args.path == "both" else [args.path]
    results = {}

    if args.which == "diff":
        # jsfp + sannysoft bad rows: path A vs path B on one server, or server vs server
        if args.base2:
            for path in paths:
                a, b = Client(args.base, path), Client(args.base2, path)
                results[path] = {"jsfp": diff(p_jsfp(a), p_jsfp(b)),
                                 "sanny_bad": [p_sanny(a).get("bad"), p_sanny(b).get("bad")]}
        else:
            a, b = Client(args.base, "stateless"), Client(args.base, "session")
            results["stateless_vs_session"] = {"jsfp": diff(p_jsfp(a), p_jsfp(b)),
                                               "sanny_bad": [p_sanny(a).get("bad"), p_sanny(b).get("bad")]}
        print(json.dumps(results, indent=1))
        return

    for path in paths:
        c = Client(args.base, path)
        results[path] = {}
        for name, fn in PROBES.items():
            if args.which not in ("all", name):
                continue
            print("[probe] %s (%s)" % (name, path), file=sys.stderr)
            res = fn(c, args.runs) if name == "clear" else fn(c)
            if name == "sanny" and not args.rows and isinstance(res, dict):
                res.pop("rows", None)
            results[path][name] = res
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()

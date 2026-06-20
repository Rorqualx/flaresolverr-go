#!/usr/bin/env python3
"""Live probe driver for flaresolverr-go (issue-driven-fix skill).

Drives the test container's /v1 API to collect structured evidence from a real
browser. Two probe shapes:
  - executeJs dump  : run JS after solve, return a JSON object (fingerprint/state)
  - raw body        : navigate a JSON/text endpoint and read solution.response

Edit BASE for your test container, then:
    python3 probe_template.py jsfp        # one probe
    python3 probe_template.py all         # every probe

Targets that reliably exhibit a CF challenge / issue cf_clearance:
  https://nowsecure.nl/            (reliable CF challenge + clearance)
  https://tls.peet.ws/api/all      (JA3/JA4 + Akamai HTTP2 fingerprint, JSON body)
  https://bot.sannysoft.com/       (automation/headless detector grid)
A site that passes natively from a clean IP proves nothing about a stuck challenge.
"""
import json
import sys
import time
import urllib.request

BASE = "http://192.168.50.185:8195/v1"  # flaresolverr-invest on Huey

# Dump the JS-visible fingerprint surface. Extend as needed; must `return` a string.
FP_JS = r"""
const o = {};
o.webdriver = navigator.webdriver;
o.platform = navigator.platform;
o.ua = navigator.userAgent;
o.languages = navigator.languages;
o.hardwareConcurrency = navigator.hardwareConcurrency;
o.deviceMemory = navigator.deviceMemory;
o.plugins = Array.prototype.map.call(navigator.plugins, p => p.name);
o.chromeRuntime = !!(window.chrome && window.chrome.runtime);
o.cdpGlobals = Object.keys(window).filter(k => /cdc_|_phantom|__nightmare|domAutomation|__webdriver|__selenium/.test(k));
o.screen = {w: screen.width, h: screen.height, aw: screen.availWidth, ah: screen.availHeight};
o.win = {ow: window.outerWidth, iw: window.innerWidth, oh: window.outerHeight, ih: window.innerHeight};
try {
  const c = document.createElement('canvas');
  const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
  const d = gl.getExtension('WEBGL_debug_renderer_info');
  o.webgl = {vendor: gl.getParameter(d.UNMASKED_VENDOR_WEBGL), renderer: gl.getParameter(d.UNMASKED_RENDERER_WEBGL)};
} catch (e) { o.webgl = 'ERR:' + e.message; }
return JSON.stringify(o);
"""


def call(body, t=120):
    req = urllib.request.Request(BASE, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=t).read())


def probe(name, url, execjs=None, raw=False, timeout=60000):
    body = {"cmd": "request.get", "url": url, "maxTimeout": timeout}
    if execjs:
        body["executeJs"] = execjs
    if raw:
        body["returnRawHtml"] = True
    t0 = time.time()
    try:
        out = call(body, t=(timeout / 1000) + 30)
    except Exception as e:  # noqa: BLE001
        return {"probe": name, "error": str(e), "elapsed": round(time.time() - t0, 1)}
    sol = out.get("solution", {})
    return {
        "probe": name, "status": out.get("status"), "http": sol.get("status"),
        "cookies": [c.get("name") for c in sol.get("cookies", [])],
        "ua": sol.get("userAgent"),
        "execjs": sol.get("executeJsResult"),
        "body_head": (sol.get("response") or "")[:1500] if raw else None,
        "elapsed": round(time.time() - t0, 1),
    }


# name -> (url, executeJs, raw)
PROBES = {
    "jsfp":  ("https://example.com", FP_JS, False),
    "tls":   ("https://tls.peet.ws/api/all", None, True),
    "clear": ("https://nowsecure.nl/", None, False),
}


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    results = {}
    for name, (url, js, raw) in PROBES.items():
        if which not in ("all", name):
            continue
        print(f"[probe] {name} -> {url}", file=sys.stderr)
        results[name] = probe(name, url, js, raw)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

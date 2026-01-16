# Cloudflare Protected Test Sites

A collection of websites with Cloudflare protection for testing FlareSolverr.

## Test Commands

```bash
# Basic test
curl -s -X POST http://localhost:8191/ \
  -H "Content-Type: application/json" \
  -d '{"cmd":"request.get","url":"URL_HERE","maxTimeout":60000}' | jq '.status, .message'
```

---

## Category 1: Comic/Manga Sites

| Site | URL | Protection Level |
|------|-----|------------------|
| ComicVine | https://comicvine.gamespot.com/ | Medium |
| MangaDex | https://mangadex.org/ | Medium |
| Bato.to | https://bato.to/ | Medium-High |
| MangaKatana | https://mangakatana.com/ | Medium |

### Test URLs:
```bash
# ComicVine - Series page
https://comicvine.gamespot.com/fire-force/4050-95557/

# ComicVine - Issue page
https://comicvine.gamespot.com/fire-force-34-extinguish-the-flames-of-despair/4000-1020567/

# MangaDex - Main page
https://mangadex.org/

# Bato.to - Main page
https://bato.to/
```

---

## Category 2: Anime Sites

| Site | URL | Protection Level |
|------|-----|------------------|
| AniList | https://anilist.co/ | Low-Medium |
| MyAnimeList | https://myanimelist.net/ | Low |
| Crunchyroll | https://www.crunchyroll.com/ | Medium |

### Test URLs:
```bash
# AniList - Anime page
https://anilist.co/anime/114236/Fire-Force-Season-2/

# MyAnimeList - Anime page
https://myanimelist.net/anime/40748/Enen_no_Shouboutai__Ni_no_Shou
```

---

## Category 3: General Sites with Cloudflare

| Site | URL | Protection Level |
|------|-----|------------------|
| Pastebin | https://pastebin.com/ | Low |
| Discord Status | https://discordstatus.com/ | Low |
| Medium | https://medium.com/ | Low-Medium |
| Cloudflare Blog | https://blog.cloudflare.com/ | Low (ironic) |

### Test URLs:
```bash
# Pastebin - Main page
https://pastebin.com/

# Discord Status
https://discordstatus.com/

# Medium article
https://medium.com/
```

---

## Category 4: E-Commerce/Retail

| Site | URL | Protection Level |
|------|-----|------------------|
| Shopify stores | Various | Medium |
| StockX | https://stockx.com/ | High |
| GOAT | https://www.goat.com/ | High |

### Test URLs:
```bash
# StockX - Main page
https://stockx.com/

# GOAT - Main page
https://www.goat.com/
```

---

## Category 5: Known Difficult Sites

| Site | URL | Protection Level | Notes |
|------|-----|------------------|-------|
| Nowsecure | https://nowsecure.nl/ | Very High | Bot detection test site |
| Fingerprint.com | https://fingerprint.com/demo/ | Very High | Fingerprinting demo |

### Test URLs:
```bash
# NowSecure - Bot detection test
https://nowsecure.nl/

# Fingerprint demo
https://fingerprint.com/demo/
```

---

## Category 6: Torrent/Indexer Sites

| Site | URL | Protection Level |
|------|-----|------------------|
| 1337x | https://1337x.to/ | Medium |
| RARBG mirrors | Various | Medium-High |
| YTS | https://yts.mx/ | Medium |

### Test URLs:
```bash
# 1337x - Main page
https://1337x.to/

# YTS - Main page
https://yts.mx/
```

---

## Batch Test Script

```bash
#!/bin/bash
# Test multiple sites

SITES=(
    "https://comicvine.gamespot.com/fire-force/4050-95557/"
    "https://mangadex.org/"
    "https://pastebin.com/"
    "https://anilist.co/"
    "https://1337x.to/"
)

for site in "${SITES[@]}"; do
    echo "Testing: $site"
    result=$(curl -s -X POST http://localhost:8191/ \
        -H "Content-Type: application/json" \
        -d "{\"cmd\":\"request.get\",\"url\":\"$site\",\"maxTimeout\":60000}" \
        | jq -r '.status + ": " + .message')
    echo "  Result: $result"
    echo ""
    sleep 2
done
```

---

## Protection Levels Explained

| Level | Description | Challenge Type |
|-------|-------------|----------------|
| **Low** | Minimal checking, usually passes immediately | None or JS challenge |
| **Medium** | Standard Cloudflare challenge | JS challenge, may require waiting |
| **Medium-High** | Stricter checking, may require interaction | JS challenge + possible Turnstile |
| **High** | Aggressive protection | Turnstile CAPTCHA likely |
| **Very High** | Bot detection focused | Multiple fingerprinting checks |

---

## Notes

1. **Rate Limiting**: Don't test too frequently or you may get temporarily blocked
2. **IP Reputation**: Fresh IPs may be treated more suspiciously
3. **Time of Day**: Some sites have stricter protection during peak hours
4. **Geo-Blocking**: Some sites may have region-specific protection
5. **Dynamic Protection**: Cloudflare adjusts protection based on threat levels

---

## Reporting Issues

If a site doesn't work, collect:
1. The full URL tested
2. The error message returned
3. Docker logs: `docker logs flaresolverr-test 2>&1 | tail -50`
4. Whether it works with Python FlareSolverr

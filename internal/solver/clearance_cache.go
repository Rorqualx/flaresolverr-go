package solver

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/publicsuffix"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Layer-2 of the clean-egress path: cache a minted cf_clearance (plus the exact
// User-Agent that minted it) keyed by registrable-domain + egress identity, so
// the expensive challenge solve (and especially the ~minutes-long two-phase
// bypass) becomes a once-per-(domain,egress) cost instead of every request.
//
// cf_clearance is bound to IP + User-Agent, so the cache key includes the egress
// identity and the entry carries the UA — reuse only happens when both match.

const (
	defaultClearanceTTL = 25 * time.Minute
	maxClearanceEntries = 2048
	cfClearanceCookie   = "cf_clearance"
)

// ClearanceEntry holds reusable Cloudflare clearance state for one (domain, egress).
type ClearanceEntry struct {
	cookies   []types.RequestCookie // ready to inject before navigation
	userAgent string
	expiresAt time.Time
}

// ClearanceCache is a bounded, TTL'd store of cf_clearance cookies.
type ClearanceCache struct {
	mu         sync.RWMutex
	entries    map[string]*ClearanceEntry
	ttl        time.Duration
	maxEntries int
	now        func() time.Time // injectable for tests
}

// NewClearanceCache creates a cache with the given TTL ceiling and max entries.
func NewClearanceCache(ttl time.Duration, maxEntries int) *ClearanceCache {
	if ttl <= 0 {
		ttl = defaultClearanceTTL
	}
	if maxEntries <= 0 {
		maxEntries = maxClearanceEntries
	}
	return &ClearanceCache{
		entries:    make(map[string]*ClearanceEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Get returns a fresh cached clearance for (domain, egress), or nil on miss/expiry.
func (c *ClearanceCache) Get(domain, egress string) *ClearanceEntry {
	if c == nil || domain == "" {
		return nil
	}
	key := clearanceKey(domain, egress)

	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if !c.now().Before(e.expiresAt) {
		// Expired — drop it.
		c.mu.Lock()
		if cur, still := c.entries[key]; still && cur == e {
			delete(c.entries, key)
		}
		c.mu.Unlock()
		return nil
	}
	return e
}

// Put stores clearance for (domain, egress) IF the cookies contain a cf_clearance.
// A no-op for non-Cloudflare solves, so it never pollutes the cache.
func (c *ClearanceCache) Put(domain, egress, userAgent string, cookies []*proto.NetworkCookie) {
	if c == nil || domain == "" || userAgent == "" {
		return
	}
	reqCookies, expiry, ok := extractClearance(cookies)
	if !ok {
		return
	}

	now := c.now()
	expiresAt := now.Add(c.ttl)
	if !expiry.IsZero() && expiry.Before(expiresAt) {
		expiresAt = expiry // honor a shorter cookie lifetime
	}
	if !expiresAt.After(now) {
		return // already expired; nothing worth caching
	}

	entry := &ClearanceEntry{cookies: reqCookies, userAgent: userAgent, expiresAt: expiresAt}
	key := clearanceKey(domain, egress)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry
	if len(c.entries) > c.maxEntries {
		c.evictLocked(now)
	}
}

// evictLocked prunes expired entries, then the soonest-to-expire if still over cap.
// Caller must hold c.mu.
func (c *ClearanceCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) > c.maxEntries {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.expiresAt.Before(oldest) {
				oldestKey, oldest = k, e.expiresAt
			}
		}
		delete(c.entries, oldestKey)
	}
}

// clearanceKey couples the registrable domain to the egress identity. cf_clearance
// is IP-bound, so a different egress must never reuse another's clearance.
func clearanceKey(domain, egress string) string {
	return domain + "|" + egress
}

// registrableDomain returns the eTLD+1 of a URL (e.g. "filecrypt.cc" for a
// container page), so all paths/subdomains of a site share one cache entry.
func registrableDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return etld1
	}
	return host
}

// proxyID derives a stable egress identity from a proxy (host:port), or "direct".
func proxyID(p *types.Proxy) string {
	if p == nil || p.URL == "" {
		return "direct"
	}
	if u, err := url.Parse(p.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return p.URL
}

// extractClearance pulls the Cloudflare clearance cookies into injectable form and
// returns the cf_clearance expiry. ok is false when no cf_clearance is present.
func extractClearance(cookies []*proto.NetworkCookie) (reqCookies []types.RequestCookie, expiry time.Time, ok bool) {
	for _, ck := range cookies {
		if ck == nil || !isClearanceCookie(ck.Name) {
			continue
		}
		reqCookies = append(reqCookies, types.RequestCookie{
			Name:     ck.Name,
			Value:    ck.Value,
			Domain:   ck.Domain,
			Path:     ck.Path,
			Secure:   ck.Secure,
			HTTPOnly: ck.HTTPOnly,
		})
		if ck.Name == cfClearanceCookie {
			ok = true
			if ck.Expires > 0 {
				expiry = time.Unix(int64(ck.Expires), 0)
			}
		}
	}
	if !ok {
		return nil, time.Time{}, false
	}
	return reqCookies, expiry, true
}

// isClearanceCookie reports whether a cookie is part of the Cloudflare clearance
// set worth carrying forward (cf_clearance plus the bot-management cookies).
func isClearanceCookie(name string) bool {
	return name == cfClearanceCookie ||
		strings.HasPrefix(name, "cf_") ||
		strings.HasPrefix(name, "__cf")
}

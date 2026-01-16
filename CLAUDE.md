# CLAUDE.md - FlareSolverr Go Project Standards

> This document defines the architecture, coding standards, and safety guidelines for the FlareSolverr Go rewrite. All contributors and AI assistants MUST follow these rules.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Directory Structure](#3-directory-structure)
4. [Coding Standards](#4-coding-standards)
5. [Safety & Security](#5-safety--security)
6. [Error Handling](#6-error-handling)
7. [Testing Requirements](#7-testing-requirements)
8. [Performance Guidelines](#8-performance-guidelines)
9. [Forbidden Patterns](#9-forbidden-patterns)
10. [Review Checklist](#10-review-checklist)

---

## 1. Project Overview

### What This Project Does

FlareSolverr-Go is a high-performance proxy server that bypasses Cloudflare and similar anti-bot protections. It:

1. Receives HTTP requests specifying a target URL
2. Opens the URL in a pooled browser instance
3. Waits for Cloudflare challenges to resolve
4. Returns cookies, HTML, and other data to the caller

### Why We Rewrote It

The original Python implementation had critical problems:

| Problem | Impact | Our Solution |
|---------|--------|--------------|
| New browser per request | 400-700MB per session | Browser pooling (150-250MB) |
| Selenium overhead | 35-45% slower | Direct CDP protocol |
| Python GIL | Limited concurrency | Go goroutines |
| No memory limits | OOM crashes | Active memory monitoring |
| Session memory leaks | Growing memory | TTL-based cleanup |

### Core Design Principles

1. **Pool, Don't Spawn** - Reuse browsers, never create on-demand
2. **Fail Fast** - Validate early, timeout aggressively
3. **Clean Up Always** - Every acquire has a release, every open has a close
4. **Isolate Failures** - One bad request cannot crash the server
5. **Measure Everything** - Metrics for memory, latency, success rates

---

## 2. Architecture

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HTTP Layer                                  │
│                      (net/http server)                              │
│                                                                     │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────────┐   │
│  │ /       │  │ /health │  │ /v1     │  │ Middleware Stack    │   │
│  │ Index   │  │ Health  │  │ API     │  │ - Recovery          │   │
│  └─────────┘  └─────────┘  └────┬────┘  │ - Logging           │   │
│                                 │       │ - Metrics           │   │
│                                 │       │ - Timeout           │   │
└─────────────────────────────────┼───────┴─────────────────────────┘
                                  │
┌─────────────────────────────────┼───────────────────────────────────┐
│                         Business Layer                              │
│                                 │                                   │
│  ┌──────────────────────────────▼──────────────────────────────┐   │
│  │                         Solver                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │   │
│  │  │ Detector    │  │ Resolver    │  │ Extractor           │  │   │
│  │  │ - Titles    │  │ - Navigate  │  │ - Cookies           │  │   │
│  │  │ - Selectors │  │ - Click     │  │ - HTML              │  │   │
│  │  │ - Status    │  │ - Wait      │  │ - Screenshots       │  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                 │                                   │
└─────────────────────────────────┼───────────────────────────────────┘
                                  │
┌─────────────────────────────────┼───────────────────────────────────┐
│                         Resource Layer                              │
│                                 │                                   │
│  ┌──────────────────────────────┴──────────────────────────────┐   │
│  │                                                              │   │
│  │  ┌─────────────────────┐      ┌─────────────────────────┐   │   │
│  │  │    Browser Pool     │      │   Session Manager       │   │   │
│  │  │                     │      │                         │   │   │
│  │  │  ┌───┐ ┌───┐ ┌───┐ │      │  Session 1: Page + TTL  │   │   │
│  │  │  │ B │ │ B │ │ B │ │◄────►│  Session 2: Page + TTL  │   │   │
│  │  │  └───┘ └───┘ └───┘ │      │  Session N: Page + TTL  │   │   │
│  │  │                     │      │                         │   │   │
│  │  │  - Acquire/Release  │      │  - Create/Destroy      │   │   │
│  │  │  - Health checks    │      │  - TTL cleanup         │   │   │
│  │  │  - Memory monitor   │      │  - Get with refresh    │   │   │
│  │  └─────────────────────┘      └─────────────────────────┘   │   │
│  │                                                              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │   Chrome/Chromium       │
                    │   (via Rod CDP)         │
                    └─────────────────────────┘
```

### Data Flow

```
Request Flow:
─────────────

1. HTTP POST /v1 ──► Middleware ──► Handler
                                       │
2. Handler validates request           │
   │                                   │
3. Handler calls Solver.Solve() ◄──────┘
   │
4. Solver acquires page:
   │
   ├─► Has session? ──► SessionManager.Get() ──► Return session's page
   │
   └─► No session? ──► BrowserPool.Acquire() ──► Create new page
   │
5. Solver.resolve():
   │
   ├─► Navigate to URL
   ├─► Detector.Detect() loop:
   │   ├─► AccessDenied? ──► Return error
   │   ├─► ChallengeActive? ──► clickVerify() ──► Continue loop
   │   └─► Solved? ──► Break loop
   │
   └─► Extractor.Extract() ──► Return Solution
   │
6. Cleanup:
   │
   ├─► Has session? ──► Keep page open
   └─► No session? ──► Close page, Release browser to pool


Memory Model:
─────────────

┌─────────────────────────────────────────────────────────────────┐
│ Go Runtime (~5MB)                                               │
├─────────────────────────────────────────────────────────────────┤
│ Browser Pool                                                    │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
│ │ Browser 1       │ │ Browser 2       │ │ Browser 3       │    │
│ │ ~100-150MB base │ │ ~100-150MB base │ │ ~100-150MB base │    │
│ │                 │ │                 │ │                 │    │
│ │ + Pages (temp)  │ │ + Pages (temp)  │ │ + Pages (temp)  │    │
│ │ ~50-100MB each  │ │ ~50-100MB each  │ │ ~50-100MB each  │    │
│ └─────────────────┘ └─────────────────┘ └─────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│ Sessions (references only, pages owned by browsers)             │
│ Session map: ~1KB per session                                   │
└─────────────────────────────────────────────────────────────────┘

Total with 3 browsers, 5 active pages: ~500-700MB
Compare to Python: 5 sessions = 2000-3500MB
```

### Component Responsibilities

| Component | Single Responsibility | Owns | Does NOT Own |
|-----------|----------------------|------|--------------|
| **Handler** | HTTP request/response | JSON encoding, validation | Business logic |
| **Solver** | Challenge resolution orchestration | Resolution flow | Browser lifecycle |
| **Detector** | Challenge status detection | Selector matching | Page navigation |
| **Resolver** | Navigation and interaction | Click actions, waits | Data extraction |
| **Extractor** | Data extraction from pages | Cookie/HTML extraction | Challenge solving |
| **BrowserPool** | Browser lifecycle | Browser instances, health | Pages, sessions |
| **SessionManager** | Session lifecycle | Session map, TTL | Browsers |
| **Config** | Configuration loading | Env vars, YAML | Runtime state |

---

## 3. Directory Structure

### Required Structure

```
flaresolverr-go/
│
├── cmd/                          # Application entrypoints
│   └── flaresolverr/
│       └── main.go               # ONLY startup code, no business logic
│
├── internal/                     # Private application code
│   │
│   ├── config/                   # Configuration
│   │   ├── config.go             # Config struct, Load()
│   │   ├── config_test.go
│   │   └── selectors.go          # Challenge selectors
│   │
│   ├── types/                    # Shared types (NO business logic)
│   │   ├── request.go            # V1Request
│   │   ├── response.go           # V1Response, Solution
│   │   ├── cookie.go             # Cookie type
│   │   ├── proxy.go              # Proxy type
│   │   ├── errors.go             # Error types
│   │   └── types_test.go
│   │
│   ├── browser/                  # Browser management
│   │   ├── pool.go               # BrowserPool
│   │   ├── pool_test.go
│   │   ├── stealth.go            # Anti-detection
│   │   └── stealth_test.go
│   │
│   ├── sessions/                 # Session management
│   │   ├── manager.go            # SessionManager
│   │   ├── manager_test.go
│   │   └── cleanup.go            # TTL cleanup routines
│   │
│   ├── solver/                   # Challenge solving
│   │   ├── solver.go             # Main Solver
│   │   ├── solver_test.go
│   │   ├── detector.go           # Challenge detection
│   │   ├── resolver.go           # Challenge resolution
│   │   ├── extractor.go          # Data extraction
│   │   └── turnstile.go          # Turnstile CAPTCHA
│   │
│   ├── handlers/                 # HTTP handlers
│   │   ├── router.go             # Route setup
│   │   ├── v1.go                 # /v1 handler
│   │   ├── health.go             # /health handler
│   │   ├── index.go              # / handler
│   │   └── handlers_test.go
│   │
│   ├── middleware/               # HTTP middleware
│   │   ├── chain.go              # Middleware chaining
│   │   ├── logging.go
│   │   ├── recovery.go
│   │   ├── metrics.go
│   │   └── timeout.go
│   │
│   └── metrics/                  # Prometheus metrics
│       └── prometheus.go
│
├── pkg/                          # Public libraries (if any)
│   └── version/
│       └── version.go            # Version from ldflags
│
├── configs/                      # Configuration files
│   └── selectors.yaml            # Challenge selectors
│
├── deployments/                  # Deployment configs
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── kubernetes/
│
├── scripts/                      # Build/test scripts
│   ├── build.sh
│   └── test.sh
│
├── docs/                         # Documentation
│   ├── API.md
│   └── MIGRATION.md
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── CLAUDE.md                     # This file
```

### File Placement Rules

| If you're adding... | Put it in... | NOT in... |
|--------------------|--------------|-----------|
| New request/response field | `internal/types/` | handlers, solver |
| New challenge selector | `configs/selectors.yaml` | hardcoded anywhere |
| New environment variable | `internal/config/config.go` | direct `os.Getenv()` |
| New HTTP endpoint | `internal/handlers/` | main.go |
| New browser flag | `internal/browser/pool.go` | solver |
| New detection logic | `internal/solver/detector.go` | resolver, extractor |
| New extraction logic | `internal/solver/extractor.go` | detector, resolver |
| New metric | `internal/metrics/prometheus.go` | scattered files |

---

## 4. Coding Standards

### 4.1 Naming Conventions

```go
// PACKAGES: lowercase, single word, no underscores
package browser    // GOOD
package browserPool // BAD
package browser_pool // BAD

// FILES: lowercase, underscores for multi-word
pool.go           // GOOD
browser_pool.go   // GOOD (if needed)
browserPool.go    // BAD
BrowserPool.go    // BAD

// TYPES: PascalCase, noun
type BrowserPool struct {}  // GOOD
type Pool struct {}         // BAD (too generic)
type HandleBrowser struct {} // BAD (verb)

// INTERFACES: PascalCase, describe behavior
type Solver interface {}    // GOOD (what it does)
type ISolver interface {}   // BAD (Hungarian notation)
type SolverInterface {}     // BAD (redundant suffix)

// FUNCTIONS: PascalCase for exported, camelCase for private
func NewPool() {}           // GOOD - exported constructor
func (p *Pool) Acquire() {} // GOOD - exported method
func (p *Pool) spawn() {}   // GOOD - private method
func (p *Pool) SpawnBrowser() {} // BAD - internal should be private

// VARIABLES: camelCase, descriptive
browserPool := NewPool()    // GOOD
bp := NewPool()             // BAD (too short)
theBrowserPoolInstance := NewPool() // BAD (too long)

// CONSTANTS: PascalCase for exported, camelCase for private
const MaxTimeout = 300      // GOOD - exported
const defaultTimeout = 60   // GOOD - private
const MAX_TIMEOUT = 300     // BAD - not Go style
const DEFAULTTIMEOUT = 60   // BAD - not Go style

// ERRORS: ErrXxx pattern
var ErrSessionNotFound = errors.New("session not found") // GOOD
var SessionNotFoundError = errors.New("...")             // BAD
var sessionNotFound = errors.New("...")                  // BAD (exported errors should be Err prefix)
```

### 4.2 Function Design

```go
// RULE: Functions should do ONE thing

// GOOD: Single responsibility
func (d *Detector) detectByTitle(title string) bool {
    for _, pattern := range d.config.ChallengeTitles {
        if strings.Contains(title, pattern) {
            return true
        }
    }
    return false
}

// BAD: Multiple responsibilities
func (d *Detector) detectAndResolve(page *rod.Page) (*Solution, error) {
    // Detecting AND resolving - split these!
}

// RULE: Accept interfaces, return structs

// GOOD
func NewSolver(pool BrowserPool, sessions SessionManager) *Solver {
    return &Solver{pool: pool, sessions: sessions}
}

// BAD
func NewSolver(pool *browser.Pool, sessions *sessions.Manager) SolverInterface {
    // Accepts concrete types, returns interface
}

// RULE: Context is always first parameter

// GOOD
func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error)

// BAD
func (s *Solver) Solve(req *Request, ctx context.Context) (*Solution, error)

// RULE: Options pattern for many optional parameters

// GOOD
type PoolOptions struct {
    Size        int
    Timeout     time.Duration
    MaxMemoryMB int
}

func NewPool(opts PoolOptions) *Pool

// BAD
func NewPool(size int, timeout time.Duration, maxMem int, headless bool, path string) *Pool
```

### 4.3 Struct Design

```go
// RULE: Group related fields, add comments for sections

// GOOD
type Config struct {
    // Server settings
    Host string
    Port int

    // Browser settings
    Headless    bool
    BrowserPath string
    PoolSize    int

    // Timeouts
    DefaultTimeout time.Duration
    MaxTimeout     time.Duration
}

// BAD: Unorganized, no grouping
type Config struct {
    Host           string
    Headless       bool
    Port           int
    DefaultTimeout time.Duration
    BrowserPath    string
    PoolSize       int
    MaxTimeout     time.Duration
}

// RULE: Embed for composition, not inheritance

// GOOD
type Session struct {
    ID        string
    Page      *rod.Page
    CreatedAt time.Time
}

func (s *Session) IsExpired(ttl time.Duration) bool {
    return time.Since(s.CreatedAt) > ttl
}

// BAD: Trying to simulate inheritance
type BaseSession struct {
    CreatedAt time.Time
}
type Session struct {
    BaseSession  // Unnecessary embedding
    ID   string
    Page *rod.Page
}
```

### 4.4 Import Organization

```go
// RULE: Three groups separated by blank lines:
// 1. Standard library
// 2. External packages
// 3. Internal packages

// GOOD
import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/go-rod/rod"
    "github.com/rs/zerolog/log"

    "github.com/Rorqualx/flaresolverr-go/internal/config"
    "github.com/Rorqualx/flaresolverr-go/internal/types"
)

// BAD: Mixed, no organization
import (
    "github.com/go-rod/rod"
    "context"
    "github.com/Rorqualx/flaresolverr-go/internal/config"
    "fmt"
    "sync"
)
```

---

## 5. Safety & Security

### 5.1 Memory Safety

```go
// RULE: Always release resources with defer

// GOOD
func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error) {
    browser, err := s.pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }
    defer s.pool.Release(browser)  // ALWAYS release

    page, err := browser.Page(nil)
    if err != nil {
        return nil, err
    }
    defer page.Close()  // ALWAYS close

    // ... rest of logic
}

// BAD: Manual cleanup (easy to miss on error paths)
func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error) {
    browser, err := s.pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }

    page, err := browser.Page(nil)
    if err != nil {
        s.pool.Release(browser)  // Must remember here
        return nil, err
    }

    // ... if panic happens here, resources leak!

    page.Close()
    s.pool.Release(browser)  // And here
    return solution, nil
}

// RULE: Use sync.Pool for frequently allocated objects

// GOOD
var bufferPool = sync.Pool{
    New: func() interface{} {
        return new(bytes.Buffer)
    },
}

func process() {
    buf := bufferPool.Get().(*bytes.Buffer)
    defer func() {
        buf.Reset()
        bufferPool.Put(buf)
    }()
    // use buf
}

// RULE: Bound all slices and maps

// GOOD
const maxSessions = 1000

func (m *Manager) Create(id string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    if len(m.sessions) >= maxSessions {
        return ErrTooManySessions
    }
    // ...
}

// BAD: Unbounded growth
func (m *Manager) Create(id string) error {
    m.sessions[id] = &Session{}  // Can grow forever
}
```

### 5.2 Concurrency Safety

```go
// RULE: Protect shared state with mutex

// GOOD
type SessionManager struct {
    mu       sync.RWMutex
    sessions map[string]*Session
}

func (m *SessionManager) Get(id string) (*Session, bool) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    s, ok := m.sessions[id]
    return s, ok
}

func (m *SessionManager) Set(id string, s *Session) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.sessions[id] = s
}

// BAD: Unprotected map access
func (m *SessionManager) Get(id string) (*Session, bool) {
    s, ok := m.sessions[id]  // DATA RACE!
    return s, ok
}

// RULE: Use channels for signaling, mutexes for state

// GOOD: Channel for shutdown signal
type Pool struct {
    done chan struct{}
}

func (p *Pool) monitor() {
    for {
        select {
        case <-p.done:
            return
        case <-time.After(30 * time.Second):
            p.checkHealth()
        }
    }
}

func (p *Pool) Close() {
    close(p.done)  // Signal all goroutines
}

// RULE: Never pass mutex by value

// GOOD
type Manager struct {
    mu sync.Mutex  // Embedded, not copied
}

// BAD
func processMutex(mu sync.Mutex) {  // COPIED! Useless lock
    mu.Lock()
    // ...
}
```

### 5.3 Input Validation

```go
// RULE: Validate ALL external input at the boundary

// GOOD: Validate in handler before passing to business logic
func (h *Handler) handleV1(w http.ResponseWriter, r *http.Request) {
    var req types.V1Request
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        h.writeError(w, http.StatusBadRequest, "invalid JSON")
        return
    }

    // Validate BEFORE passing to solver
    if err := req.Validate(); err != nil {
        h.writeError(w, http.StatusBadRequest, err.Error())
        return
    }

    // Now solver can trust the input
    solution, err := h.solver.Solve(r.Context(), &req)
}

// GOOD: Comprehensive validation
func (r *V1Request) Validate() error {
    // Required fields
    if r.Cmd == "" {
        return errors.New("cmd is required")
    }

    // Enum validation
    switch r.Cmd {
    case CmdRequestGet, CmdRequestPost, CmdSessionsCreate, CmdSessionsList, CmdSessionsDestroy:
        // valid
    default:
        return fmt.Errorf("unknown command: %s", r.Cmd)
    }

    // URL validation
    if r.URL != "" {
        u, err := url.Parse(r.URL)
        if err != nil {
            return fmt.Errorf("invalid URL: %w", err)
        }
        if u.Scheme != "http" && u.Scheme != "https" {
            return errors.New("URL must be http or https")
        }
    }

    // Bound numeric values
    if r.MaxTimeout < 0 {
        return errors.New("maxTimeout cannot be negative")
    }
    if r.MaxTimeout > 300000 {
        r.MaxTimeout = 300000  // Cap at 5 minutes
    }

    return nil
}

// RULE: Sanitize data before use in browser

// GOOD
func (s *Solver) submitForm(page *rod.Page, targetURL, postData string) error {
    // Escape HTML to prevent XSS in our generated form
    escapedURL := html.EscapeString(targetURL)

    values, err := url.ParseQuery(postData)
    if err != nil {
        return fmt.Errorf("invalid postData: %w", err)
    }

    // Build form with escaped values
    // ...
}
```

### 5.4 Timeout Safety

```go
// RULE: Every operation that can block MUST have a timeout

// GOOD
func (p *Pool) Acquire(ctx context.Context) (*rod.Browser, error) {
    select {
    case browser := <-p.available:
        return browser, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    case <-time.After(p.timeout):
        return nil, ErrPoolTimeout
    }
}

// BAD: Can block forever
func (p *Pool) Acquire() *rod.Browser {
    return <-p.available  // Blocks forever if pool empty
}

// RULE: Propagate context through all layers

// GOOD
func (h *Handler) handleV1(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()  // Has request deadline
    solution, err := h.solver.Solve(ctx, &req)  // Pass it down
}

func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error) {
    browser, err := s.pool.Acquire(ctx)  // Respects deadline
    // ...
    return s.resolve(ctx, page, req)  // Keep passing
}

// RULE: Set explicit timeouts for browser operations

// GOOD
func (s *Solver) navigate(ctx context.Context, page *rod.Page, url string) error {
    return page.Context(ctx).Navigate(url)  // Timeout from context
}

// Alternative: explicit timeout
func (s *Solver) navigate(page *rod.Page, url string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    return page.Context(ctx).Navigate(url)
}
```

---

## 6. Error Handling

### 6.1 Error Design

```go
// RULE: Use sentinel errors for expected conditions

// In types/errors.go
var (
    ErrSessionNotFound     = errors.New("session not found")
    ErrBrowserPoolExhausted = errors.New("browser pool exhausted")
    ErrChallengeTimeout    = errors.New("challenge resolution timed out")
    ErrAccessDenied        = errors.New("access denied by target site")
)

// Usage
func (m *Manager) Get(id string) (*Session, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()

    s, ok := m.sessions[id]
    if !ok {
        return nil, ErrSessionNotFound  // Sentinel error
    }
    return s, nil
}

// Caller can check
if errors.Is(err, ErrSessionNotFound) {
    // Handle missing session
}

// RULE: Wrap errors with context

// GOOD
func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error) {
    browser, err := s.pool.Acquire(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to acquire browser: %w", err)
    }

    page, err := browser.Page(nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create page: %w", err)
    }

    if err := page.Navigate(req.URL); err != nil {
        return nil, fmt.Errorf("failed to navigate to %s: %w", req.URL, err)
    }
}

// BAD: No context
func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error) {
    browser, err := s.pool.Acquire(ctx)
    if err != nil {
        return nil, err  // Caller has no idea what failed
    }
}

// RULE: Use custom error types for rich errors

type ChallengeError struct {
    Type    string  // "access_denied", "timeout", "unsolvable"
    URL     string
    Message string
    Err     error
}

func (e *ChallengeError) Error() string {
    return e.Message
}

func (e *ChallengeError) Unwrap() error {
    return e.Err
}

// Usage
return nil, &ChallengeError{
    Type:    "access_denied",
    URL:     req.URL,
    Message: "Access denied. The target site has blocked this IP.",
    Err:     ErrAccessDenied,
}
```

### 6.2 Error Handling Patterns

```go
// RULE: Handle errors immediately, don't defer

// GOOD
result, err := doSomething()
if err != nil {
    return fmt.Errorf("doSomething failed: %w", err)
}
// continue with result

// BAD: Error checked later
result, err := doSomething()
// ... other code ...
if err != nil {  // Easy to forget or misplace
    return err
}

// RULE: Don't ignore errors silently

// GOOD
if err := page.Close(); err != nil {
    log.Warn().Err(err).Msg("failed to close page")
    // Continue anyway, but we logged it
}

// BAD
_ = page.Close()  // Silently ignored

// ACCEPTABLE: Explicit ignore with comment
// Ignore error: cleanup should not affect response
_ = page.Close()

// RULE: Panic only for programming errors, not runtime errors

// ACCEPTABLE: Programming error (should never happen in production)
func MustParse(s string) *Config {
    cfg, err := Parse(s)
    if err != nil {
        panic(fmt.Sprintf("invalid config: %v", err))
    }
    return cfg
}

// BAD: Panicking on runtime error
func (p *Pool) Acquire() *rod.Browser {
    browser, err := p.acquire()
    if err != nil {
        panic(err)  // This could happen in production!
    }
    return browser
}
```

---

## 7. Testing Requirements

### 7.1 Test Coverage Requirements

| Package | Minimum Coverage | Critical Paths |
|---------|-----------------|----------------|
| `types/` | 90% | Validation logic |
| `config/` | 80% | Loading, defaults |
| `browser/` | 70% | Pool acquire/release |
| `sessions/` | 80% | Create/destroy, TTL |
| `solver/` | 70% | Detection, extraction |
| `handlers/` | 80% | All endpoints |

### 7.2 Test Organization

```go
// RULE: Test file next to implementation

browser/
├── pool.go
├── pool_test.go      // Tests for pool.go
├── stealth.go
└── stealth_test.go   // Tests for stealth.go

// RULE: Use table-driven tests

func TestDetector_Detect(t *testing.T) {
    tests := []struct {
        name     string
        title    string
        want     ChallengeStatus
    }{
        {
            name:  "normal page",
            title: "My Website",
            want:  StatusSolved,
        },
        {
            name:  "cloudflare challenge",
            title: "Just a moment...",
            want:  StatusChallengeActive,
        },
        {
            name:  "access denied",
            title: "Access denied",
            want:  StatusAccessDenied,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := NewDetector(config.DefaultSelectors())
            got := d.detectByTitle(tt.title)
            if got != tt.want {
                t.Errorf("detectByTitle() = %v, want %v", got, tt.want)
            }
        })
    }
}

// RULE: Use subtests for setup/teardown

func TestPool(t *testing.T) {
    pool := setupTestPool(t)
    defer pool.Close()

    t.Run("Acquire", func(t *testing.T) {
        // test acquire
    })

    t.Run("Release", func(t *testing.T) {
        // test release
    })

    t.Run("Timeout", func(t *testing.T) {
        // test timeout
    })
}

// RULE: Use testify for assertions (optional but recommended)

import "github.com/stretchr/testify/assert"

func TestConfig_Load(t *testing.T) {
    cfg, err := config.Load()

    assert.NoError(t, err)
    assert.Equal(t, 8191, cfg.Port)
    assert.True(t, cfg.Headless)
}
```

### 7.3 Integration Test Requirements

```go
// RULE: Integration tests use real browser (tagged)

//go:build integration

func TestSolver_RealChallenge(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }

    // Uses real browser pool
    pool, _ := browser.NewPool(testConfig)
    defer pool.Close()

    // ... test against real site
}

// Run with: go test -tags=integration ./...
```

---

## 8. Performance Guidelines

### 8.1 Memory Limits

```go
// RULE: Bound all buffers

const (
    maxHTMLSize       = 10 * 1024 * 1024  // 10MB max HTML
    maxScreenshotSize = 5 * 1024 * 1024   // 5MB max screenshot
    maxCookies        = 100               // Max cookies per response
)

func (e *Extractor) extractHTML(page *rod.Page) (string, error) {
    html, err := page.HTML()
    if err != nil {
        return "", err
    }

    if len(html) > maxHTMLSize {
        return html[:maxHTMLSize], nil  // Truncate
    }
    return html, nil
}

// RULE: Prefer streaming over buffering

// GOOD: Stream response
func (h *Handler) handleV1(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)  // Streams directly
}

// BAD: Buffer then write
func (h *Handler) handleV1(w http.ResponseWriter, r *http.Request) {
    data, _ := json.Marshal(response)  // Allocates buffer
    w.Write(data)
}
```

### 8.2 Concurrency Limits

```go
// RULE: Limit concurrent operations

const maxConcurrentSolves = 10

type Solver struct {
    semaphore chan struct{}
}

func NewSolver() *Solver {
    return &Solver{
        semaphore: make(chan struct{}, maxConcurrentSolves),
    }
}

func (s *Solver) Solve(ctx context.Context, req *Request) (*Solution, error) {
    // Acquire semaphore
    select {
    case s.semaphore <- struct{}{}:
        defer func() { <-s.semaphore }()
    case <-ctx.Done():
        return nil, ctx.Err()
    }

    // ... actual solving
}
```

### 8.3 Caching

```go
// RULE: Cache expensive computations

type Detector struct {
    // Compiled regex patterns (cached)
    patterns []*regexp.Regexp
}

func NewDetector(cfg *SelectorsConfig) *Detector {
    d := &Detector{}

    // Compile patterns once at startup
    for _, pattern := range cfg.Challenge.Patterns {
        d.patterns = append(d.patterns, regexp.MustCompile(pattern))
    }

    return d
}

// RULE: Use sync.Once for one-time initialization

var (
    defaultConfig     *Config
    defaultConfigOnce sync.Once
)

func GetDefaultConfig() *Config {
    defaultConfigOnce.Do(func() {
        defaultConfig = loadConfig()
    })
    return defaultConfig
}
```

---

## 9. Forbidden Patterns

### DO NOT DO THESE:

```go
// ❌ FORBIDDEN: Global mutable state
var globalPool *Pool  // BAD: Use dependency injection

// ❌ FORBIDDEN: init() with side effects
func init() {
    pool = NewPool()  // BAD: Hard to test, order-dependent
}

// ❌ FORBIDDEN: Naked goroutines without tracking
func (s *Solver) Solve() {
    go s.doBackground()  // BAD: No way to wait or cancel
}

// ❌ FORBIDDEN: Ignoring context cancellation
func (s *Solver) Solve(ctx context.Context) {
    // BAD: Never checks ctx.Done()
    for {
        result := s.try()
        if result != nil {
            return result
        }
    }
}

// ❌ FORBIDDEN: Unbounded retries
func (s *Solver) Solve() {
    for {  // BAD: Infinite loop
        if err := s.try(); err == nil {
            return
        }
    }
}

// ❌ FORBIDDEN: Panic in library code
func (p *Pool) Acquire() *Browser {
    b, err := p.acquire()
    if err != nil {
        panic(err)  // BAD: Let caller handle
    }
    return b
}

// ❌ FORBIDDEN: Business logic in handlers
func (h *Handler) handleV1(w http.ResponseWriter, r *http.Request) {
    // BAD: Challenge solving logic here
    page.Navigate(req.URL)
    for {
        if hasChallenge(page) {
            clickVerify(page)
        }
    }
    // Should call: h.solver.Solve(ctx, req)
}

// ❌ FORBIDDEN: Direct os.Getenv in business logic
func (s *Solver) Solve() {
    timeout := os.Getenv("TIMEOUT")  // BAD: Use config
}

// ❌ FORBIDDEN: Hardcoded selectors in code
func (d *Detector) Detect(page *rod.Page) {
    if page.MustHas("#cf-challenge-running") {  // BAD: Use config
        return StatusChallenge
    }
}

// ❌ FORBIDDEN: Sleep without context
func (s *Solver) waitForChallenge() {
    time.Sleep(5 * time.Second)  // BAD: Not cancellable
}

// ✅ CORRECT: Use timer with context
func (s *Solver) waitForChallenge(ctx context.Context) error {
    select {
    case <-time.After(5 * time.Second):
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}

// ❌ FORBIDDEN: Returning nil error with nil result
func (m *Manager) Get(id string) (*Session, error) {
    s, ok := m.sessions[id]
    if !ok {
        return nil, nil  // BAD: Ambiguous
    }
    return s, nil
}

// ✅ CORRECT: Return error or valid result
func (m *Manager) Get(id string) (*Session, error) {
    s, ok := m.sessions[id]
    if !ok {
        return nil, ErrSessionNotFound
    }
    return s, nil
}
```

---

## 10. Review Checklist

Before submitting code, verify:

### Architecture
- [ ] Code is in the correct package per directory structure
- [ ] No business logic in handlers (only in solver/)
- [ ] No HTTP concerns in solver (only in handlers/)
- [ ] Types are in types/ package, not scattered

### Safety
- [ ] All resources released with defer
- [ ] All shared state protected by mutex
- [ ] All blocking operations have timeouts
- [ ] Context propagated through all layers
- [ ] All external input validated

### Code Quality
- [ ] Functions do ONE thing
- [ ] No magic numbers (use named constants)
- [ ] Errors wrapped with context
- [ ] No ignored errors (or explicitly commented)
- [ ] No forbidden patterns used

### Testing
- [ ] Unit tests added for new code
- [ ] Table-driven tests used where appropriate
- [ ] Edge cases covered (nil, empty, max values)
- [ ] Tests pass: `go test ./...`

### Performance
- [ ] No unbounded allocations
- [ ] Expensive operations cached
- [ ] No unnecessary copying

### Documentation
- [ ] Public functions have doc comments
- [ ] Complex logic has inline comments
- [ ] README updated if needed

---

## Quick Reference

### Import This First
```go
import (
    "context"
    "fmt"
    "sync"
    "time"
)
```

### Standard Error Check
```go
if err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

### Standard Mutex Pattern
```go
m.mu.Lock()
defer m.mu.Unlock()
```

### Standard Context Timeout
```go
ctx, cancel := context.WithTimeout(ctx, timeout)
defer cancel()
```

### Standard Resource Cleanup
```go
resource, err := acquire()
if err != nil {
    return err
}
defer release(resource)
```

### Standard Goroutine with Shutdown
```go
go func() {
    for {
        select {
        case <-done:
            return
        case <-ticker.C:
            doWork()
        }
    }
}()
```

---

*Last updated: January 2025*
*Maintainer: FlareSolverr Team*

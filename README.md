# FlareSolverr Go Edition

A high-performance Cloudflare bypass proxy server written in Go. This is a complete rewrite of the original Python FlareSolverr with significant performance improvements.

## Features

- **Browser Pooling** - Reuses browser instances instead of spawning new ones per request (150-250MB vs 400-700MB)
- **Direct CDP Protocol** - Uses Chrome DevTools Protocol directly, bypassing Selenium overhead
- **Go Concurrency** - Native goroutines for better concurrency than Python's GIL
- **Memory Management** - Active memory monitoring with automatic browser recycling
- **Session Support** - TTL-based session management with automatic cleanup
- **Cloudflare Bypass** - Solves JavaScript challenges and Turnstile CAPTCHAs
- **Docker Support** - Production-ready Docker image with Xvfb

## Quick Start

### Docker (Recommended)
```bash
docker run -d -p 8191:8191 --name flaresolverr flaresolverr-go
```

### From Source
```bash
go build -o flaresolverr ./cmd/flaresolverr
./flaresolverr
```

## API Usage

### Solve a Cloudflare Challenge
```bash
curl -X POST http://localhost:8191/ \
  -H "Content-Type: application/json" \
  -d '{"cmd": "request.get", "url": "https://example.com", "maxTimeout": 60000}'
```

### Response
```json
{
  "status": "ok",
  "message": "Challenge solved successfully",
  "solution": {
    "url": "https://example.com/",
    "status": 200,
    "response": "<html>...</html>",
    "cookies": [...],
    "userAgent": "Mozilla/5.0..."
  }
}
```

## Configuration

Environment variables:
- `PORT` - Server port (default: 8191)
- `BROWSER_POOL_SIZE` - Number of browser instances (default: 3)
- `MAX_TIMEOUT` - Maximum request timeout (default: 300s)
- `HEADLESS` - Run browsers headless (default: true)

See [CLAUDE.md](CLAUDE.md) for full documentation.

## Bug Fixes in This Version

This release includes 12 bug fixes:
1. Goroutine leak prevention in event handlers
2. Context-aware sleep for proper cancellation
3. Dynamic poll attempts based on timeout
4. Race-free browser pool availability checks
5. Safe lock/unlock patterns with defer
6. Buffered JSON responses
7. Safe type assertions in buffer pools
8. Config parse failure logging
9. Timeout validation
10. HTTP request body cleanup
11. Config bounds validation
12. Updated Dockerfile for Go 1.24

## Attribution

Built with [Claude Code](https://claude.ai/code) by Anthropic

## License

MIT License - See [LICENSE](LICENSE) for details.

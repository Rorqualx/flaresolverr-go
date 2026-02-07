// Package assets provides embedded static files for the application.
// Using Go's embed package allows for single-binary deployment without
// external file dependencies.
package assets

import (
	"bytes"
	"embed"
	"html"
	"html/template"
	"io/fs"
	"regexp"
)

// Templates embeds all HTML templates.
//
//go:embed templates/*.html
var Templates embed.FS

// GetTemplate parses and returns a named template from the embedded filesystem.
func GetTemplate(name string) (*template.Template, error) {
	return template.ParseFS(Templates, "templates/"+name)
}

// ReadTemplate returns the raw content of a template file.
func ReadTemplate(name string) ([]byte, error) {
	return fs.ReadFile(Templates, "templates/"+name)
}

// sanitizeVersion removes any potentially dangerous characters from the version string.
// This prevents XSS via build-time ldflags injection.
// Only allows alphanumeric characters, dots, dashes, underscores, and plus signs.
var versionSanitizer = regexp.MustCompile(`[^a-zA-Z0-9.\-_+]`)

// SanitizeVersion sanitizes a version string to prevent XSS attacks.
// Returns "unknown" if the result is empty after sanitization.
func SanitizeVersion(version string) string {
	// First HTML escape, then remove any remaining suspicious characters
	escaped := html.EscapeString(version)
	sanitized := versionSanitizer.ReplaceAllString(escaped, "")
	if sanitized == "" {
		return "unknown"
	}
	// Limit length to prevent DoS via extremely long version strings
	if len(sanitized) > 100 {
		sanitized = sanitized[:100]
	}
	return sanitized
}

// HealthPageData contains the data for rendering the health page.
type HealthPageData struct {
	Version   string
	GoVersion string
	Uptime    string
	PoolSize  int
	Sessions  int
}

// healthPageTemplate is the pre-compiled health page template using html/template
// for automatic XSS protection.
var healthPageTemplate = template.Must(template.New("health").Parse(healthPageHTML))

// RenderHealthPage renders the health page with the given data.
// Uses html/template for automatic XSS escaping of all values.
func RenderHealthPage(data HealthPageData) (string, error) {
	// Pre-sanitize version as defense in depth
	data.Version = SanitizeVersion(data.Version)

	var buf bytes.Buffer
	if err := healthPageTemplate.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// healthPageHTML is the template source for the health page.
// SECURITY: This template uses html/template which auto-escapes all values.
// Additionally, the Version field is pre-sanitized before rendering.
const healthPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FlareSolverr Health</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            max-width: 500px;
        }
        h1 {
            color: #00d9ff;
            margin-bottom: 0.5rem;
            font-size: 2.5rem;
        }
        .subtitle {
            color: #888;
            margin-bottom: 2rem;
        }
        .status {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            background: rgba(0, 255, 128, 0.1);
            border: 1px solid rgba(0, 255, 128, 0.3);
            border-radius: 8px;
            color: #00ff80;
            font-weight: 600;
            margin-bottom: 1.5rem;
        }
        .status::before {
            content: '';
            width: 10px;
            height: 10px;
            background: #00ff80;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .info {
            text-align: left;
            background: rgba(0,0,0,0.2);
            padding: 1rem;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.9rem;
        }
        .info div {
            padding: 0.25rem 0;
        }
        .label {
            color: #888;
        }
        footer {
            margin-top: 2rem;
            color: #666;
            font-size: 0.8rem;
        }
        a {
            color: #00d9ff;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>FlareSolverr</h1>
        <p class="subtitle">Go Edition</p>
        <div class="status">Service Healthy</div>
        <div class="info">
            <div><span class="label">Version:</span> {{.Version}}</div>
            <div><span class="label">Go Version:</span> {{.GoVersion}}</div>
            <div><span class="label">Uptime:</span> {{.Uptime}}</div>
            <div><span class="label">Pool Size:</span> {{.PoolSize}}</div>
            <div><span class="label">Sessions:</span> {{.Sessions}}</div>
        </div>
        <footer>
            <a href="https://github.com/FlareSolverr/FlareSolverr" target="_blank">GitHub</a>
        </footer>
    </div>
</body>
</html>`

// HealthPage is the raw HTML template for backward compatibility.
// Deprecated: Use RenderHealthPage() instead for XSS-safe rendering.
var HealthPage = healthPageHTML

// APIDocumentation provides embedded API documentation.
var APIDocumentation = `# FlareSolverr API Documentation

## Overview
FlareSolverr is a proxy server that uses a headless browser to bypass Cloudflare
and other anti-bot protections.

## Endpoints

### POST /v1
Main API endpoint for all commands.

### GET /health
Health check endpoint.

### GET /metrics (if enabled)
Prometheus metrics endpoint.

## Commands

### request.get
Fetch a URL using GET method.

**Request:**
` + "```json" + `
{
    "cmd": "request.get",
    "url": "https://example.com",
    "maxTimeout": 60000
}
` + "```" + `

### request.post
Submit a POST request with data.

**Request:**
` + "```json" + `
{
    "cmd": "request.post",
    "url": "https://example.com/login",
    "postData": "username=user&password=pass",
    "maxTimeout": 60000
}
` + "```" + `

### sessions.create
Create a persistent browser session.

### sessions.list
List all active sessions.

### sessions.destroy
Destroy a session and free its resources.

## Response Format
` + "```json" + `
{
    "status": "ok",
    "message": "Challenge solved successfully",
    "solution": {
        "url": "https://example.com",
        "status": 200,
        "response": "<html>...</html>",
        "cookies": [],
        "userAgent": "Mozilla/5.0..."
    }
}
` + "```" + `
`

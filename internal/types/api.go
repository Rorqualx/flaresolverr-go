package types

// Request represents an incoming API request.
// This matches the FlareSolverr API specification.
type Request struct {
	Cmd               string          `json:"cmd"`
	URL               string          `json:"url,omitempty"`
	Session           string          `json:"session,omitempty"`
	SessionTTL        int             `json:"session_ttl_minutes,omitempty"`
	MaxTimeout        int             `json:"maxTimeout,omitempty"`
	Cookies           []RequestCookie `json:"cookies,omitempty"`
	ReturnOnlyCookies bool            `json:"returnOnlyCookies,omitempty"`
	Proxy             *Proxy          `json:"proxy,omitempty"`
	PostData          string          `json:"postData,omitempty"`
	Screenshot        bool            `json:"screenshot,omitempty"` // Capture screenshot and return as base64
}

// RequestCookie represents a cookie to be set before navigation.
type RequestCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
}

// Proxy contains proxy configuration for a request.
type Proxy struct {
	URL      string `json:"url"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Response represents an API response.
// This matches the FlareSolverr API specification.
type Response struct {
	Status    string     `json:"status"`
	Message   string     `json:"message"`
	StartTime int64      `json:"startTimestamp"`
	EndTime   int64      `json:"endTimestamp"`
	Version   string     `json:"version"`
	Solution  *Solution  `json:"solution,omitempty"`
	Sessions  []string   `json:"sessions,omitempty"`
}

// Solution contains the result of a successful solve.
type Solution struct {
	URL            string            `json:"url"`
	Status         int               `json:"status"`
	Headers        map[string]string `json:"headers,omitempty"`
	Response       string            `json:"response"`
	Cookies        []Cookie          `json:"cookies"`
	UserAgent      string            `json:"userAgent"`
	Screenshot     string            `json:"screenshot,omitempty"`     // Base64 encoded PNG screenshot
	TurnstileToken string            `json:"turnstileToken,omitempty"` // cf-turnstile-response token if present
}

// Cookie represents a browser cookie.
type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires,omitempty"`
	Size     int     `json:"size,omitempty"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	Session  bool    `json:"session,omitempty"`
	SameSite string  `json:"sameSite,omitempty"`
}

// Commands supported by the API.
const (
	CmdRequestGet     = "request.get"
	CmdRequestPost    = "request.post"
	CmdSessionsCreate = "sessions.create"
	CmdSessionsList   = "sessions.list"
	CmdSessionsDestroy = "sessions.destroy"
)

// Status values for API responses.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

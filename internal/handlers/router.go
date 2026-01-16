package handlers

import (
	"net/http"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Route represents a single API route.
type Route struct {
	Path    string
	Method  string
	Handler func(http.ResponseWriter, *http.Request)
}

// Router handles HTTP request routing for the FlareSolverr API.
type Router struct {
	handler *Handler
}

// NewRouter creates a new Router with the given Handler.
func NewRouter(h *Handler) *Router {
	return &Router{handler: h}
}

// ServeHTTP implements http.Handler and routes requests to appropriate handlers.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch {
	case req.URL.Path == "/health" || req.URL.Path == "/v1":
		r.handler.HandleHealth(w, req)

	case req.URL.Path == "/" || req.URL.Path == "/api":
		if req.Method != http.MethodPost {
			r.handler.HandleMethodNotAllowed(w, req)
			return
		}
		r.handler.HandleAPI(w, req)

	default:
		r.handler.HandleNotFound(w, req)
	}
}

// routeCommand routes API commands to their handlers.
func (h *Handler) routeCommand(w http.ResponseWriter, r *http.Request, req *types.Request, startTime time.Time) {
	switch req.Cmd {
	case types.CmdRequestGet:
		h.handleRequest(w, r.Context(), req, false, startTime)
	case types.CmdRequestPost:
		h.handleRequest(w, r.Context(), req, true, startTime)
	case types.CmdSessionsCreate:
		h.handleSessionCreate(w, r.Context(), req, startTime)
	case types.CmdSessionsList:
		h.handleSessionList(w, startTime)
	case types.CmdSessionsDestroy:
		h.handleSessionDestroy(w, req, startTime)
	default:
		h.writeError(w, "Unknown command: "+req.Cmd, startTime)
	}
}

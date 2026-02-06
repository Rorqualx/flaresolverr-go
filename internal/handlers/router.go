package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// validCommands is a map of all valid API commands for fast lookup.
// This prevents processing of unknown commands that could cause unexpected behavior.
var validCommands = map[string]bool{
	types.CmdRequestGet:      true,
	types.CmdRequestPost:     true,
	types.CmdSessionsCreate:  true,
	types.CmdSessionsList:    true,
	types.CmdSessionsDestroy: true,
}

// routeCommand routes API commands to their handlers.
// Commands must be in the validCommands map to be processed.
func (h *Handler) routeCommand(w http.ResponseWriter, r *http.Request, req *types.Request, startTime time.Time) {
	// Early validation: check if command is in the valid commands map
	if !validCommands[req.Cmd] {
		h.writeError(w, fmt.Sprintf("Unknown command: %q", req.Cmd), startTime)
		return
	}

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
		// This should never be reached due to validCommands check above,
		// but kept for safety
		h.writeError(w, fmt.Sprintf("Unknown command: %q", req.Cmd), startTime)
	}
}

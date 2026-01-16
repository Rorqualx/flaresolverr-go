// Package middleware provides HTTP middleware components.
package middleware

import (
	"net/http"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog/log"
)

// Recovery returns middleware that recovers from panics and logs the error.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		defer func() {
			if err := recover(); err != nil {
				log.Error().
					Interface("error", err).
					Str("stack", string(debug.Stack())).
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("Panic recovered")

				writeErrorResponse(w, http.StatusInternalServerError, "Internal server error", startTime)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

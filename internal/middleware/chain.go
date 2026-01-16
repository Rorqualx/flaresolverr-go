package middleware

import "net/http"

// Chain creates a middleware chain from a list of middleware functions.
// Middleware are applied in order, so Chain(A, B, C) will execute as A(B(C(handler))).
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

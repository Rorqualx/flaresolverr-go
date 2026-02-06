// Package main provides the entry point for FlareSolverr.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Import for side effects - registers pprof handlers
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/handlers"
	"github.com/Rorqualx/flaresolverr-go/internal/middleware"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/pkg/version"
)

func main() {
	// Handle --version flag early, before any initialization
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("FlareSolverr %s\n", version.Full())
		return
	}

	// Load configuration
	cfg := config.Load()

	// Setup logging first so validation warnings are visible
	setupLogging(cfg.LogLevel)

	// Validate configuration (Bug 12: config bounds validation)
	cfg.Validate()

	// Print banner
	printBanner()

	// Initialize browser pool
	log.Info().Msg("Initializing browser pool...")
	pool, err := browser.NewPool(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize browser pool")
	}

	// Initialize session manager with pool reference for browser cleanup
	sessionMgr := session.NewManager(cfg, pool)

	// Create handler
	handler := handlers.New(pool, sessionMgr, cfg)

	// Build middleware chain
	var finalHandler http.Handler = handler

	// Apply middleware (in reverse order - last applied runs first)
	// 1. Recovery (outermost - catches panics from everything)
	// 2. Logging (logs all requests)
	// 3. Rate limiting (if enabled)
	// 4. API key authentication (if enabled)
	// 5. Security headers
	// 6. CORS (handles preflight)

	finalHandler = middleware.CORS(middleware.CORSConfig{
		AllowedOrigins: cfg.CORSAllowedOrigins,
	})(finalHandler)

	finalHandler = middleware.SecurityHeaders(finalHandler)

	// Apply API key authentication middleware if enabled
	// This MUST be applied before rate limiting so unauthenticated requests
	// are rejected before consuming rate limit tokens
	if cfg.APIKeyEnabled {
		log.Info().Msg("API key authentication enabled")
		finalHandler = middleware.APIKey(cfg)(finalHandler)
	}

	// Create rate limiter middleware with cleanup support
	var rateLimiter *middleware.RateLimiterMiddleware
	if cfg.RateLimitEnabled {
		log.Info().
			Int("requests_per_minute", cfg.RateLimitRPM).
			Bool("trust_proxy", cfg.TrustProxy).
			Msg("Rate limiting enabled")
		rateLimiter = middleware.NewRateLimitMiddleware(cfg.RateLimitRPM, cfg.TrustProxy)
		finalHandler = rateLimiter.Handler()(finalHandler)
	}

	finalHandler = middleware.Logging(finalHandler)
	finalHandler = middleware.Recovery(finalHandler)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	server := &http.Server{
		Addr:              addr,
		Handler:           finalHandler,
		ReadTimeout:       cfg.MaxTimeout + 10*time.Second,
		WriteTimeout:      cfg.MaxTimeout + 10*time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second, // Prevent slowloris attacks
	}

	// Start pprof server if enabled
	// WARNING: pprof should only be enabled in development/debugging
	// as it exposes detailed runtime information
	var pprofServer *http.Server
	if cfg.PProfEnabled {
		pprofAddr := fmt.Sprintf("%s:%d", cfg.PProfBindAddr, cfg.PProfPort)
		pprofServer = &http.Server{
			Addr:         pprofAddr,
			Handler:      http.DefaultServeMux, // pprof registers to DefaultServeMux
			ReadTimeout:  60 * time.Second,
			WriteTimeout: 60 * time.Second, // Profiles can take time
		}

		go func() {
			log.Warn().
				Str("addr", pprofAddr).
				Msg("WARNING: pprof profiling server started - exposes runtime internals, use for debugging only")

			if err := pprofServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("pprof server failed")
			}
		}()
	}

	// Start main server in goroutine
	go func() {
		log.Info().
			Str("address", addr).
			Int("pool_size", cfg.BrowserPoolSize).
			Bool("rate_limit_enabled", cfg.RateLimitEnabled).
			Msg("FlareSolverr is ready to accept requests")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Stop receiving signals to prevent double-shutdown
	signal.Stop(quit)

	log.Info().Msg("Shutting down...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown main server
	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Server shutdown error")
	}

	// Shutdown pprof server if running
	if pprofServer != nil {
		if err := pprofServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("pprof server shutdown error")
		}
	}

	// Close rate limiter to stop cleanup goroutine
	if rateLimiter != nil {
		rateLimiter.Close()
	}

	// Close session manager
	if err := sessionMgr.Close(); err != nil {
		log.Error().Err(err).Msg("Session manager close error")
	}

	// Close browser pool
	if err := pool.Close(); err != nil {
		log.Error().Err(err).Msg("Browser pool close error")
	}

	log.Info().Msg("Shutdown complete")
}

// setupLogging configures zerolog based on the log level.
func setupLogging(level string) {
	// Use console writer for prettier output
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})

	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// printBanner prints the startup banner.
func printBanner() {
	banner := `
 _____ _                ____        _
|  ___| | __ _ _ __ ___/ ___|  ___ | |_   _____ _ __ _ __
| |_  | |/ _' | '__/ _ \___ \ / _ \| \ \ / / _ \ '__| '__|
|  _| | | (_| | | |  __/___) | (_) | |\ V /  __/ |  | |
|_|   |_|\__,_|_|  \___|____/ \___/|_| \_/ \___|_|  |_|
                                                    Go Edition
`
	fmt.Println(banner)
	log.Info().
		Str("version", version.Full()).
		Str("go_version", version.GoVersion()).
		Msg("Starting FlareSolverr")
}

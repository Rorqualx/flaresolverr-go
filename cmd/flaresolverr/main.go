// Package main provides the entry point for FlareSolverr.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // Import for side effects - registers pprof handlers
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/browser"
	"github.com/Rorqualx/flaresolverr-go/internal/config"
	"github.com/Rorqualx/flaresolverr-go/internal/dashboard"
	"github.com/Rorqualx/flaresolverr-go/internal/handlers"
	"github.com/Rorqualx/flaresolverr-go/internal/middleware"
	"github.com/Rorqualx/flaresolverr-go/internal/selectors"
	"github.com/Rorqualx/flaresolverr-go/internal/session"
	"github.com/Rorqualx/flaresolverr-go/internal/solver"
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

	os.Exit(run())
}

// run starts the server and blocks until it shuts down. It returns the process
// exit code. Nothing in here may call log.Fatal once the browser pool exists:
// an abrupt exit would orphan every Chrome process the pool launched.
func run() int {
	// Load configuration
	cfg := config.Load()

	// Setup logging first so validation warnings are visible
	fileLog := setupLogging(cfg.LogLevel, cfg.LogFile)

	// Validate configuration (Bug 12: config bounds validation)
	cfg.Validate()

	// Validate may have replaced an invalid level; apply the final value
	zerolog.SetGlobalLevel(parseLogLevel(cfg.LogLevel))

	// Print banner
	printBanner()

	// Claim the listen address before launching any browser. A port that is
	// already in use is the most common startup failure, and it must be found
	// while there is nothing to clean up yet.
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error().Err(err).Str("address", addr).Msg("Failed to bind listen address")
		return 1
	}

	// Initialize browser pool
	log.Info().Msg("Initializing browser pool...")
	pool, err := browser.NewPool(cfg)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize browser pool")
		// Ignore error: exiting anyway
		_ = listener.Close()
		return 1
	}

	// Initialize session manager with pool reference for browser cleanup
	sessionMgr := session.NewManager(cfg, pool)

	// Initialize selectors manager with optional hot-reload and remote fetch
	var selectorsManager *selectors.Manager
	if cfg.SelectorsPath != "" || cfg.SelectorsHotReload || cfg.SelectorsRemoteURL != "" {
		var err error
		selectorsManager, err = selectors.NewManagerWithRemote(
			cfg.SelectorsPath,
			cfg.SelectorsHotReload,
			cfg.SelectorsRemoteURL,
			cfg.SelectorsRemoteRefresh,
		)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create selectors manager, using embedded defaults")
			selectorsManager = selectors.GetManager()
		}
		if cfg.SelectorsHotReload && cfg.SelectorsPath != "" {
			log.Info().Str("path", cfg.SelectorsPath).Msg("Selectors hot-reload enabled")
		}
		if cfg.SelectorsRemoteURL != "" {
			log.Info().
				Str("url", cfg.SelectorsRemoteURL).
				Dur("refresh", cfg.SelectorsRemoteRefresh).
				Msg("Remote selector fetch enabled")
		}
	} else {
		selectorsManager = selectors.GetManager()
	}

	// Create handler
	handler := handlers.NewWithSelectors(pool, sessionMgr, cfg, selectorsManager)

	// Create dashboard (enabled by default)
	// TTY: full TUI dashboard | Non-TTY (Docker): periodic log-based stats reporter
	var dash *dashboard.Dashboard
	var logReporter *dashboard.LogReporter
	if cfg.DashboardEnabled {
		if dashboard.IsTTY() {
			dash = dashboard.New(pool, sessionMgr, handler.DomainStats(), time.Now())
			// The TUI owns the terminal, but LOG_FILE must keep receiving logs
			dash.SetFileLog(fileLog)
		} else {
			logReporter = dashboard.NewLogReporter(pool, sessionMgr, handler.DomainStats(), time.Now(), 30*time.Second)
		}
	}

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
	if dash != nil {
		finalHandler = dashboard.RecordRequests(dash.Events())(finalHandler)
	} else if logReporter != nil {
		finalHandler = dashboard.RecordRequests(logReporter.Events())(finalHandler)
	}
	finalHandler = middleware.Recovery(finalHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:        addr,
		Handler:     finalHandler,
		ReadTimeout: cfg.MaxTimeout + 10*time.Second,
		// A request can run for its timeout, then the reconnect bypass, plus
		// the wait for a pooled browser. A shorter write timeout dropped the
		// connection after all the work had been done.
		WriteTimeout:      cfg.MaxTimeout + solver.ReconnectBypassBudget + cfg.BrowserPoolTimeout + 10*time.Second,
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

	// Start main server in goroutine. A serve failure is reported on serverErr
	// so shutdown still closes the pool.
	serverErr := make(chan error, 1)
	go func() {
		log.Info().
			Str("address", addr).
			Int("pool_size", cfg.BrowserPoolSize).
			Bool("rate_limit_enabled", cfg.RateLimitEnabled).
			Msg("FlareSolverr is ready to accept requests")

		// Check for updates in background (non-blocking)
		go func() {
			if latestVersion, releaseURL := version.CheckForUpdate(); latestVersion != "" {
				log.Info().
					Str("current", version.Full()).
					Str("latest", latestVersion).
					Str("url", releaseURL).
					Msg("A newer version of FlareSolverr is available")
			}
		}()

		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Start dashboard or log reporter
	if dash != nil {
		dash.Start()
	} else if logReporter != nil {
		logReporter.Start()
	}

	// Wait for an interrupt signal, a server failure, or the dashboard being
	// quit. The TUI swallows ctrl+c in raw mode, so quitting it is the user's
	// way of stopping the server; leaving the process running with no UI and
	// no console logs helped nobody.
	var dashDone <-chan struct{}
	if dash != nil {
		dashDone = dash.Done()
	}

	exitCode := 0
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
	case <-dashDone:
		log.Info().Msg("Dashboard closed")
	case err := <-serverErr:
		log.Error().Err(err).Msg("Server failed")
		exitCode = 1
	}

	// Stop receiving signals to prevent double-shutdown
	signal.Stop(quit)

	// Give the terminal back before logging the shutdown
	if dash != nil {
		dash.Stop()
	}

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

	// Stop log reporter (the dashboard was stopped above)
	if logReporter != nil {
		logReporter.Stop()
	}

	// Close selectors manager to stop file watcher
	if selectorsManager != nil {
		if err := selectorsManager.Close(); err != nil {
			log.Error().Err(err).Msg("Selectors manager close error")
		}
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
	return exitCode
}

// setupLogging configures zerolog to write to the console and, if logFile is
// set, to that file as well. It returns the file writer (nil if there is none)
// so the dashboard can keep the file fed while it owns the terminal.
func setupLogging(level, logFile string) io.Writer {
	var output io.Writer = zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}

	// Add file logging if LOG_FILE is set
	var fileLog io.Writer
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Failed to open log file %s: %v\n", logFile, err)
		} else {
			fileLog = f
			output = io.MultiWriter(output, f)
			fmt.Printf("Logging to file: %s\n", logFile)
		}
	}

	log.Logger = log.Output(output)
	zerolog.SetGlobalLevel(parseLogLevel(level))
	return fileLog
}

// parseLogLevel maps a LOG_LEVEL value to a zerolog level, ignoring case and
// surrounding space. Unknown values fall back to info.
func parseLogLevel(level string) zerolog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	default:
		return zerolog.InfoLevel
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

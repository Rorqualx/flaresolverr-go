# Build stage - use BUILDPLATFORM for native compilation speed
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Target architecture arguments for cross-compilation
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application for target architecture
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags "-s -w -X github.com/Rorqualx/flaresolverr-go/pkg/version.Version=${VERSION}" \
    -o /flaresolverr \
    ./cmd/flaresolverr

# Final stage
# Alpine 3.23 ships Chromium 149. Do not move to 3.24 without re-testing: its
# Chromium 152 package never finishes loading some pages (bot.sannysoft.com is
# one), also when started by hand with no flags from this project. A browser
# upgrade changes the fingerprint, so re-run the probe suite before any bump.
FROM alpine:3.23

# Install Chromium, xvfb, and required dependencies
# mesa-* packages provide OpenGL/WebGL software rendering via SwiftShader/llvmpipe
RUN apk add --no-cache \
    chromium \
    chromium-chromedriver \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    font-noto \
    font-noto-cjk \
    dumb-init \
    xvfb \
    xvfb-run \
    mesa-gl \
    mesa-gles \
    mesa-dri-gallium \
    mesa-egl \
    mesa-gbm \
    libxcomposite \
    libxdamage \
    libxrandr \
    libxi \
    libxtst \
    libxscrnsaver \
    alsa-lib \
    at-spi2-core \
    cups-libs \
    libdrm \
    libxkbcommon

# Optional packages that may not exist on all architectures. Kept in a separate
# RUN, installed one at a time: a trailing `|| true` on the required install
# above would also hide a missing chromium, and a single `apk add` of the whole
# list installs nothing if any one package is unavailable.
RUN for pkg in chromium-swiftshader mesa-vulkan-swrast libva libva-glx; do \
        if apk add --no-cache "$pkg" >/dev/null 2>&1; then \
            echo "optional package installed: $pkg"; \
        else \
            echo "WARNING: optional package unavailable on this architecture, skipped: $pkg"; \
        fi; \
    done

# Fail the build if the browser this image exists to run cannot start
RUN chromium-browser --version

# Create non-root user
RUN addgroup -g 1000 flaresolverr && \
    adduser -D -u 1000 -G flaresolverr flaresolverr

# Copy binary from builder
COPY --from=builder /flaresolverr /usr/local/bin/flaresolverr

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set Chrome binary path
ENV BROWSER_PATH=/usr/bin/chromium-browser

# Server settings
ENV HOST=0.0.0.0 \
    PORT=8191

# Browser settings - HEADLESS=false uses xvfb for virtual display
ENV HEADLESS=false \
    BROWSER_POOL_SIZE=3 \
    BROWSER_POOL_TIMEOUT=30s \
    MAX_MEMORY_MB=2048

# Session settings
ENV SESSION_TTL=30m \
    SESSION_CLEANUP_INTERVAL=1m \
    MAX_SESSIONS=20

# Timeout settings
ENV DEFAULT_TIMEOUT=60s \
    MAX_TIMEOUT=300s

# Logging
ENV LOG_LEVEL=info \
    LOG_HTML=false

# Security (Rate limiting)
ENV RATE_LIMIT_ENABLED=true \
    RATE_LIMIT_RPM=60

# Display settings for xvfb
ENV DISPLAY=:99

# WebGL/SwiftShader settings
# Force software rendering via SwiftShader for consistent WebGL support
ENV LIBGL_ALWAYS_SOFTWARE=1 \
    GALLIUM_DRIVER=llvmpipe \
    LP_NUM_THREADS=4

# Create directories and set permissions
RUN mkdir -p /home/flaresolverr/.cache /tmp/.X11-unix /tmp/rod && \
    chown -R flaresolverr:flaresolverr /home/flaresolverr /tmp/rod && \
    chmod 1777 /tmp/.X11-unix

# Declare /tmp/rod as an anonymous mount point so Rod's Chromium user-data dirs
# never accumulate in the container's writable layer (GitHub issue #6). With
# this directive, `docker run` without --tmpfs/-v still creates an ephemeral
# anonymous volume that is reclaimed by `docker rm -v` instead of bloating
# docker.img. Bind-mount it or use --tmpfs for explicit control.
VOLUME ["/tmp/rod"]

# Switch to non-root user
USER flaresolverr

# Expose ports (main API and metrics)
EXPOSE 8191 8192

# Health check. 127.0.0.1 rather than localhost: busybox wget uses the first
# address it resolves, and that can be ::1 while the server listens on IPv4.
# Shell form so PORT is read at run time.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget -q -T 5 --spider "http://127.0.0.1:${PORT:-8191}/health" || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/docker-entrypoint.sh"]

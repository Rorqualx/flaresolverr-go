# Build stage - use BUILDPLATFORM for native compilation speed
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

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
FROM alpine:3.19

# Install Chromium, xvfb, and required dependencies
# mesa-gl and mesa-dri-gallium provide OpenGL/WebGL software rendering
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
    mesa-dri-gallium \
    mesa-egl \
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
    MAX_SESSIONS=100

# Timeout settings
ENV DEFAULT_TIMEOUT=60s \
    MAX_TIMEOUT=300s

# Logging
ENV LOG_LEVEL=info \
    LOG_HTML=false

# Metrics (Prometheus)
ENV PROMETHEUS_ENABLED=false \
    PROMETHEUS_PORT=8192

# Security (Rate limiting)
ENV RATE_LIMIT_ENABLED=true \
    RATE_LIMIT_RPM=60

# Display settings for xvfb
ENV DISPLAY=:99

# Create directories and set permissions
RUN mkdir -p /home/flaresolverr/.cache /tmp/.X11-unix && \
    chown -R flaresolverr:flaresolverr /home/flaresolverr && \
    chmod 1777 /tmp/.X11-unix

# Switch to non-root user
USER flaresolverr

# Expose ports (main API and metrics)
EXPOSE 8191 8192

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8191/health || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/docker-entrypoint.sh"]

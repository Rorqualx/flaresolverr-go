#!/bin/sh
set -e

# Start Xvfb in the background
# -screen 0 creates a screen with 1920x1080 resolution and 24-bit color depth
# -ac disables access control restrictions
Xvfb :99 -screen 0 1920x1080x24 -ac &

# Wait for Xvfb to be ready
sleep 1

# Verify Xvfb is running
if ! pgrep -x Xvfb > /dev/null; then
    echo "ERROR: Failed to start Xvfb"
    exit 1
fi

echo "Xvfb started successfully on display :99"

# Run the main application
exec /usr/local/bin/flaresolverr "$@"

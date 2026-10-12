#!/bin/sh
set -e

DISPLAY_NUM=99
X_SOCKET="/tmp/.X11-unix/X${DISPLAY_NUM}"
X_LOCK="/tmp/.X${DISPLAY_NUM}-lock"
# Seconds to wait for Xvfb to create its socket before giving up
X_START_TIMEOUT=15

# After `exec` below, this shell's PID is the application's PID.
APP_PID=$$

# A container that was killed (docker kill, OOM, power loss) keeps its writable
# layer, so the previous Xvfb's lock and socket are still there on restart.
# The X server treats the lock as live whenever a process with the recorded PID
# exists, and inside a container the same PIDs are handed out again, so it
# refuses to start: "Server is already active for display 99". Nothing else can
# be using this display yet, so the leftovers are always stale.
rm -f "$X_LOCK" "$X_SOCKET"

# Xvfb is started in both display modes, including HEADLESS=true. Pooled
# headless browsers do not need it (measured: with no X server and DISPLAY
# unset they launch, solve and report an identical fingerprint), but the
# reconnect bypass launches a headful Chrome, and without a display its second
# phase fails with "Chrome did not start debugging endpoint". Skipping Xvfb for
# headless would silently remove that fallback.
#
# Run Xvfb under a small supervisor. If Xvfb exits for any reason other than
# the container being stopped, the browsers have lost their display and cannot
# recover, so the application is killed. The container then exits non-zero and
# the restart policy brings up a clean one.
#   -screen 0 creates a 1920x1080 screen with 24-bit color depth
#   -ac disables access control (the socket is only reachable in the container)
#   -nolisten tcp keeps the X server off the network
(
    stopping=""
    trap 'stopping=1' TERM INT
    Xvfb ":${DISPLAY_NUM}" -screen 0 1920x1080x24 -ac -nolisten tcp || true
    if [ -n "$stopping" ]; then
        exit 0
    fi
    echo "ERROR: Xvfb exited unexpectedly; stopping the container so it can be restarted" >&2
    kill -KILL "$APP_PID" 2>/dev/null
) &
SUPERVISOR_PID=$!

# Wait for the X socket instead of sleeping a fixed time
waited=0
while [ ! -S "$X_SOCKET" ]; do
    if ! kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
        echo "ERROR: Failed to start Xvfb" >&2
        exit 1
    fi
    if [ "$waited" -ge "$((X_START_TIMEOUT * 10))" ]; then
        echo "ERROR: Xvfb did not create ${X_SOCKET} within ${X_START_TIMEOUT}s" >&2
        exit 1
    fi
    sleep 0.1
    waited=$((waited + 1))
done

echo "Xvfb started successfully on display :${DISPLAY_NUM}"

# Run the main application. `exec` replaces this shell so signals from
# dumb-init reach the application directly.
exec /usr/local/bin/flaresolverr "$@"

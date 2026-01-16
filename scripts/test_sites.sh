#!/bin/bash
# FlareSolverr Test Script
# Tests multiple Cloudflare-protected sites

FLARESOLVERR_URL="${FLARESOLVERR_URL:-http://localhost:8191/}"
TIMEOUT="${TIMEOUT:-60000}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test sites grouped by category
declare -A SITES
SITES["ComicVine"]="https://comicvine.gamespot.com/fire-force/4050-95557/"
SITES["MangaDex"]="https://mangadex.org/"
SITES["AniList"]="https://anilist.co/"
SITES["Pastebin"]="https://pastebin.com/"
SITES["1337x"]="https://1337x.to/"
SITES["YTS"]="https://yts.mx/"
SITES["NowSecure"]="https://nowsecure.nl/"

echo "========================================"
echo "FlareSolverr Test Suite"
echo "========================================"
echo "Server: $FLARESOLVERR_URL"
echo "Timeout: ${TIMEOUT}ms"
echo ""

# Check if server is up
echo -n "Checking server health... "
health=$(curl -s "${FLARESOLVERR_URL}health" | grep -o '"status":"ok"')
if [ -z "$health" ]; then
    echo -e "${RED}FAILED${NC}"
    echo "Server is not responding. Make sure FlareSolverr is running."
    exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# Test each site
passed=0
failed=0

for name in "${!SITES[@]}"; do
    url="${SITES[$name]}"
    echo -n "Testing $name... "

    # Make request
    response=$(curl -s -X POST "$FLARESOLVERR_URL" \
        -H "Content-Type: application/json" \
        -d "{\"cmd\":\"request.get\",\"url\":\"$url\",\"maxTimeout\":$TIMEOUT}" \
        --max-time 120)

    # Check result
    status=$(echo "$response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    message=$(echo "$response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)

    if [ "$status" = "ok" ]; then
        echo -e "${GREEN}PASSED${NC} - $message"
        ((passed++))
    else
        echo -e "${RED}FAILED${NC} - $message"
        ((failed++))
    fi

    # Small delay between requests
    sleep 2
done

echo ""
echo "========================================"
echo "Results: ${GREEN}$passed passed${NC}, ${RED}$failed failed${NC}"
echo "========================================"

# Exit with error code if any failed
if [ $failed -gt 0 ]; then
    exit 1
fi

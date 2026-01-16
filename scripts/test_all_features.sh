#!/bin/bash
# Comprehensive FlareSolverr Feature Test
# Tests: pooling, sessions, concurrent requests, all API commands
# Tracks: performance, response times, memory usage

FLARESOLVERR_URL="${FLARESOLVERR_URL:-http://localhost:8191}"
TIMEOUT="${TIMEOUT:-60000}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

passed=0
failed=0
declare -a response_times
declare -a test_names

# Get current timestamp in ms
get_ms() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        python3 -c 'import time; print(int(time.time() * 1000))'
    else
        # Linux
        date +%s%3N
    fi
}

test_result() {
    local name="$1"
    local response="$2"
    local duration="$3"
    local expected_status="${4:-ok}"

    status=$(echo "$response" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    message=$(echo "$response" | grep -o '"message":"[^"]*"' | head -1 | cut -d'"' -f4 | cut -c1-50)

    # Store for summary
    test_names+=("$name")
    response_times+=("$duration")

    if [ "$status" = "$expected_status" ]; then
        echo -e "  ${GREEN}✓${NC} $name ${CYAN}(${duration}ms)${NC}"
        echo -e "    └─ $message"
        ((passed++))
        return 0
    else
        echo -e "  ${RED}✗${NC} $name ${CYAN}(${duration}ms)${NC}"
        echo -e "    └─ $message"
        ((failed++))
        return 1
    fi
}

get_container_stats() {
    docker stats flaresolverr-test --no-stream --format "{{.MemUsage}}|{{.CPUPerc}}" 2>/dev/null
}

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}       FlareSolverr Comprehensive Feature Test                 ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Initial stats
initial_stats=$(get_container_stats)
echo -e "${YELLOW}Initial Container Stats:${NC}"
echo "  Memory: $(echo $initial_stats | cut -d'|' -f1)"
echo "  CPU: $(echo $initial_stats | cut -d'|' -f2)"
echo ""

# ============================================
# TEST 1: Health Check
# ============================================
echo -e "${YELLOW}[1/8] Health Check${NC}"
start=$(get_ms)
response=$(curl -s "${FLARESOLVERR_URL}/health")
end=$(get_ms)
duration=$((end - start))
test_result "Health endpoint" "$response" "$duration"
echo ""

# ============================================
# TEST 2: Basic GET Request
# ============================================
echo -e "${YELLOW}[2/8] Basic GET Request${NC}"
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"request.get","url":"https://httpbin.org/get","maxTimeout":30000}')
end=$(get_ms)
duration=$((end - start))
test_result "GET request to httpbin" "$response" "$duration"
echo ""

# ============================================
# TEST 3: Cloudflare Protected Site
# ============================================
echo -e "${YELLOW}[3/8] Cloudflare Protected Site${NC}"
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"request.get","url":"https://comicvine.gamespot.com/fire-force/4050-95557/","maxTimeout":60000}')
end=$(get_ms)
duration=$((end - start))
test_result "ComicVine (Cloudflare)" "$response" "$duration"
echo ""

# ============================================
# TEST 4: Session Management
# ============================================
echo -e "${YELLOW}[4/8] Session Management${NC}"

# Create session
echo "  Creating session..."
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"sessions.create","session":"test-session-1"}')
end=$(get_ms)
duration=$((end - start))
test_result "Create session" "$response" "$duration"

# List sessions
echo "  Listing sessions..."
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"sessions.list"}')
end=$(get_ms)
duration=$((end - start))
test_result "List sessions" "$response" "$duration"

# Use session for request
echo "  Using session for request..."
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"request.get","url":"https://httpbin.org/cookies","session":"test-session-1","maxTimeout":30000}')
end=$(get_ms)
duration=$((end - start))
test_result "Request with session" "$response" "$duration"

# Destroy session
echo "  Destroying session..."
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{"cmd":"sessions.destroy","session":"test-session-1"}')
end=$(get_ms)
duration=$((end - start))
test_result "Destroy session" "$response" "$duration"
echo ""

# ============================================
# TEST 5: Cookie Handling
# ============================================
echo -e "${YELLOW}[5/8] Cookie Handling${NC}"
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{
        "cmd":"request.get",
        "url":"https://httpbin.org/cookies",
        "cookies":[
            {"name":"test_cookie","value":"test_value"},
            {"name":"another_cookie","value":"another_value"}
        ],
        "maxTimeout":30000
    }')
end=$(get_ms)
duration=$((end - start))
test_result "Request with cookies" "$response" "$duration"
echo ""

# ============================================
# TEST 6: POST Request
# ============================================
echo -e "${YELLOW}[6/8] POST Request${NC}"
start=$(get_ms)
response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
    -H "Content-Type: application/json" \
    -d '{
        "cmd":"request.post",
        "url":"https://httpbin.org/post",
        "postData":"key1=value1&key2=value2",
        "maxTimeout":30000
    }')
end=$(get_ms)
duration=$((end - start))
test_result "POST request" "$response" "$duration"
echo ""

# ============================================
# TEST 7: Concurrent Requests (Browser Pool Test)
# ============================================
echo -e "${YELLOW}[7/8] Concurrent Requests (Browser Pool)${NC}"
echo "  Sending 3 concurrent requests..."

concurrent_start=$(get_ms)

# Start 3 requests in parallel
(
    start=$(get_ms)
    curl -s -X POST "$FLARESOLVERR_URL/" \
        -H "Content-Type: application/json" \
        -d '{"cmd":"request.get","url":"https://httpbin.org/delay/2","maxTimeout":30000}' \
        > /tmp/flare_test_1.json
    end=$(get_ms)
    echo $((end - start)) > /tmp/flare_time_1.txt
) &
pid1=$!

(
    start=$(get_ms)
    curl -s -X POST "$FLARESOLVERR_URL/" \
        -H "Content-Type: application/json" \
        -d '{"cmd":"request.get","url":"https://httpbin.org/delay/2","maxTimeout":30000}' \
        > /tmp/flare_test_2.json
    end=$(get_ms)
    echo $((end - start)) > /tmp/flare_time_2.txt
) &
pid2=$!

(
    start=$(get_ms)
    curl -s -X POST "$FLARESOLVERR_URL/" \
        -H "Content-Type: application/json" \
        -d '{"cmd":"request.get","url":"https://httpbin.org/delay/2","maxTimeout":30000}' \
        > /tmp/flare_test_3.json
    end=$(get_ms)
    echo $((end - start)) > /tmp/flare_time_3.txt
) &
pid3=$!

# Wait for all to complete
wait $pid1 $pid2 $pid3
concurrent_end=$(get_ms)
total_concurrent=$((concurrent_end - concurrent_start))

# Check results
test_result "Concurrent request 1" "$(cat /tmp/flare_test_1.json)" "$(cat /tmp/flare_time_1.txt)"
test_result "Concurrent request 2" "$(cat /tmp/flare_test_2.json)" "$(cat /tmp/flare_time_2.txt)"
test_result "Concurrent request 3" "$(cat /tmp/flare_test_3.json)" "$(cat /tmp/flare_time_3.txt)"
echo -e "  ${CYAN}Total concurrent time: ${total_concurrent}ms${NC}"
echo -e "  ${CYAN}(Sequential would be ~3x longer)${NC}"

# Cleanup
rm -f /tmp/flare_test_*.json /tmp/flare_time_*.txt
echo ""

# ============================================
# TEST 8: Multiple Cloudflare Sites
# ============================================
echo -e "${YELLOW}[8/8] Multiple Cloudflare Sites${NC}"

sites=(
    "https://pastebin.com/"
    "https://anilist.co/"
)

for site in "${sites[@]}"; do
    echo "  Testing: $site"
    start=$(get_ms)
    response=$(curl -s -X POST "$FLARESOLVERR_URL/" \
        -H "Content-Type: application/json" \
        -d "{\"cmd\":\"request.get\",\"url\":\"$site\",\"maxTimeout\":60000}" \
        --max-time 90)
    end=$(get_ms)
    duration=$((end - start))
    test_result "$(echo $site | sed 's|https://||' | sed 's|/||g')" "$response" "$duration"
done
echo ""

# ============================================
# PERFORMANCE SUMMARY
# ============================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Performance Summary:${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

# Calculate stats
total_time=0
min_time=999999
max_time=0
for t in "${response_times[@]}"; do
    total_time=$((total_time + t))
    if [ "$t" -lt "$min_time" ]; then min_time=$t; fi
    if [ "$t" -gt "$max_time" ]; then max_time=$t; fi
done
avg_time=$((total_time / ${#response_times[@]}))

echo ""
echo -e "  ${CYAN}Response Times:${NC}"
echo "    Min: ${min_time}ms"
echo "    Max: ${max_time}ms"
echo "    Avg: ${avg_time}ms"
echo "    Total: ${total_time}ms"
echo ""

# Final container stats
final_stats=$(get_container_stats)
echo -e "  ${CYAN}Container Stats:${NC}"
echo "    Memory: $(echo $final_stats | cut -d'|' -f1)"
echo "    CPU: $(echo $final_stats | cut -d'|' -f2)"
echo ""

# Per-test breakdown
echo -e "  ${CYAN}Per-Test Breakdown:${NC}"
for i in "${!test_names[@]}"; do
    printf "    %-30s %6sms\n" "${test_names[$i]}" "${response_times[$i]}"
done
echo ""

# ============================================
# FINAL RESULTS
# ============================================
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
total=$((passed + failed))
echo -e "  Test Results: ${GREEN}$passed passed${NC} / ${RED}$failed failed${NC} / $total total"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

echo ""
if [ $failed -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi

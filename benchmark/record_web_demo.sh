#!/usr/bin/env bash
# ARGUS Web Demo Recorder
#
# Captures a sequence of screenshots from the live web dashboard
# during a scan, then stitches them into an animated GIF for the README.
#
# Pipeline:
#   1. Start benchmark Docker containers
#   2. Start the ARGUS web server (background)
#   3. Trigger a slow scan via API
#   4. Loop: capture a screenshot every 0.5s for ~25 seconds
#   5. Stitch frames into GIF with ffmpeg
#   6. Tear down server and containers
#
# Usage:
#   ./benchmark/record_web_demo.sh           # default
#   ./benchmark/record_web_demo.sh --keep-up # leave services running

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

ASSETS_DIR="${PROJECT_ROOT}/benchmark/assets"
FRAMES_DIR="${ASSETS_DIR}/web_frames"
GIF_FILE="${ASSETS_DIR}/argus-web-action.gif"
COMPOSE_FILE="${PROJECT_ROOT}/benchmark/docker-compose.yml"
PORT=8765
WEB_PID_FILE="/tmp/argus-web.pid"

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
# Chrome expects comma-separated dimensions, not x
WINDOW_SIZE="1500,1100"

KEEP_UP=0
for arg in "$@"; do
    case "$arg" in
        --keep-up) KEEP_UP=1 ;;
    esac
done

log() { echo -e "\033[1;33m[record_web_demo]\033[0m $*"; }

# ----- Preflight -----
for tool in docker curl ffmpeg; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool not found" >&2
        exit 1
    fi
done
if [[ ! -x "$CHROME" ]]; then
    echo "ERROR: Chrome not found at $CHROME" >&2
    exit 1
fi

mkdir -p "$ASSETS_DIR"
rm -rf "$FRAMES_DIR"
mkdir -p "$FRAMES_DIR"

# ----- Cleanup function -----
cleanup() {
    if [[ -f "$WEB_PID_FILE" ]]; then
        local pid
        pid=$(cat "$WEB_PID_FILE")
        kill "$pid" 2>/dev/null || true
        rm -f "$WEB_PID_FILE"
    fi
    if [[ ${KEEP_UP} -eq 0 ]]; then
        docker compose -f "${COMPOSE_FILE}" down >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ----- Step 1: Start containers -----
log "Starting benchmark scenarios..."
docker compose -f "${COMPOSE_FILE}" up -d >/dev/null 2>&1

log "Waiting for endpoints..."
for port in 8001 8002 8003 8004; do
    for _ in {1..15}; do
        if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then break; fi
        sleep 0.3
    done
done

# ----- Step 2: Start web server -----
# Generate a fresh demo token and pass it to the server.
# ARGUS_WEB_ALLOW_PRIVATE=1 enables scanning the local benchmark containers.
ARGUS_WEB_TOKEN_DEMO="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
log "Starting ARGUS web server on port ${PORT}..."
ARGUS_WEB_TOKEN="$ARGUS_WEB_TOKEN_DEMO" \
ARGUS_WEB_ALLOW_PRIVATE=1 \
"${PROJECT_ROOT}/.venv/bin/python" -m uvicorn argus.web.server:create_app \
    --host 127.0.0.1 --port "${PORT}" --factory --log-level warning >/tmp/argus-web.log 2>&1 &
echo $! > "$WEB_PID_FILE"

for _ in {1..20}; do
    if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then break; fi
    sleep 0.3
done

if ! curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
    log "ERROR: web server did not start"
    cat /tmp/argus-web.log
    exit 1
fi

log "Web server up: http://127.0.0.1:${PORT}/"

# ----- Step 3: Trigger scan -----
log "Triggering scan with demo pacing (1.5s/event for ~30s total runtime)..."
curl -sX POST "http://127.0.0.1:${PORT}/api/scan/start" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ARGUS_WEB_TOKEN_DEMO}" \
    -d '{
        "target_name": "ARGUS Gauntlet",
        "mcp_urls": ["http://localhost:8001", "http://localhost:8003", "http://localhost:8004"],
        "agent_endpoint": "http://localhost:8002/chat",
        "timeout": 180,
        "demo_pace_seconds": 1.5
    }' >/dev/null

# ----- Step 4: Capture frames -----
log "Capturing 40 frames at 0.8s intervals (~32s total)..."
for i in $(seq 1 40); do
    frame_num=$(printf "%03d" "$i")
    "$CHROME" \
        --headless \
        --disable-gpu \
        --window-size=${WINDOW_SIZE} \
        --force-device-scale-factor=1 \
        --virtual-time-budget=1500 \
        --hide-scrollbars \
        --screenshot="${FRAMES_DIR}/frame_${frame_num}.png" \
        "http://127.0.0.1:${PORT}/" \
        >/dev/null 2>&1 || true
    printf "  frame %s/40  " "$frame_num"
    sleep 0.8
done
echo

# ----- Step 5: Stitch into GIF -----
log "Stitching frames into GIF..."
ffmpeg -y -framerate 5 -i "${FRAMES_DIR}/frame_%03d.png" \
    -vf "scale=1100:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5" \
    -loop 0 \
    "${GIF_FILE}" 2>&1 | tail -3

GIF_SIZE=$(wc -c < "${GIF_FILE}" | tr -d ' ')
GIF_SIZE_MB=$(echo "scale=2; ${GIF_SIZE} / 1024 / 1024" | bc)

log "GIF rendered: ${GIF_FILE} (${GIF_SIZE_MB} MB)"
log "Done."
echo
echo "  Asset:    ${GIF_FILE}"
echo "  Size:     ${GIF_SIZE_MB} MB"
echo

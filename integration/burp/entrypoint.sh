#!/usr/bin/env bash
# Boot Burp Suite Community headlessly with the freshly built MCP extension
# loaded, so the integration suite can drive it through the bridge.
#
# The three things that make a GUI app like Burp start unattended:
#
#   1. A display. Burp is a Swing app and throws HeadlessException without one,
#      so we run a throwaway Xvfb and a minimal window manager (fluxbox) to give
#      the startup wizard a focused top-level window.
#
#   2. EULA. On a fresh Java-prefs store Burp prints the licence agreement to
#      the console and blocks on "Do you accept? (y/n)" on STDIN *before* it
#      opens any window. We feed it a stream of "y" (see FEED below). Once
#      accepted, burp.eula lands in the prefs store under $BURP_HOME/.java.
#
#   3. The project wizard. Community cannot use named project files, so it always
#      opens the GUI wizard (Temporary project -> Next -> Start Burp). Both steps
#      default to the button that Enter activates, so once the wizard is up we
#      send Return via xdotool to walk through it with defaults.
#
# Config files on the launch line:
#   --user-config-file  registers the extension (extender.extensions) -> its
#                       Jetty API server comes up on $BURP_MCP_SERVER_PORT.
#   --config-file       sets the proxy listener to all_interfaces:8080 so the
#                       host-side runner can reach it through published ports.
set -uo pipefail

BURP_JAR=${BURP_JAR:-/opt/burp/burpsuite_community.jar}
EXT_JAR=${EXT_JAR:-/opt/burp/extension.jar}
BURP_HOME=${BURP_HOME:-/burp-home}
USER_CONFIG=${USER_CONFIG:-/config/user-config.json}
PROJECT_CONFIG=${PROJECT_CONFIG:-/config/project-config.json}
API_PORT=${BURP_MCP_SERVER_PORT:-8081}
PROXY_PORT=${BURP_PROXY_PORT:-8080}
DISPLAY_NUM=${DISPLAY_NUM:-:99}
LOG=${BURP_LOG:-$BURP_HOME/burp.log}

export HOME="$BURP_HOME"
export DISPLAY="$DISPLAY_NUM"
mkdir -p "$BURP_HOME/.java"

log() { echo "[entrypoint] $*" >&2; }

[ -f "$BURP_JAR" ] || { log "FATAL: Burp jar not found at $BURP_JAR (mount it read-only)"; exit 1; }
[ -f "$EXT_JAR" ]  || { log "FATAL: extension jar not found at $EXT_JAR (mount it read-only)"; exit 1; }

# The user-config registers the extension by absolute path; render @EXT_JAR@ so
# the seed does not hardcode a path that differs between build and run.
runtime_user_config=$BURP_HOME/user-config.json
sed "s#@EXT_JAR@#${EXT_JAR}#g" "$USER_CONFIG" > "$runtime_user_config"

# --- 1. Display -----------------------------------------------------------
log "starting Xvfb on $DISPLAY"
Xvfb "$DISPLAY" -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 &
XVFB_PID=$!
for _ in $(seq 1 40); do
  xdpyinfo -display "$DISPLAY" >/dev/null 2>&1 && break
  sleep 0.25
done
xdpyinfo -display "$DISPLAY" >/dev/null 2>&1 || { log "FATAL: no X display after 10s"; exit 1; }
fluxbox >/dev/null 2>&1 &

# --- 2. Launch Burp, feeding the EULA on STDIN ----------------------------
# `yes` keeps STDIN open with an endless stream of "y", so Burp never hits EOF
# mid-prompt (which makes it exit) and every y/n console prompt is accepted.
#
# burp.mcp.allowed.hosts='*' disables the extension's remote-IP allowlist for
# this disposable instance: the API port is published only to 127.0.0.1 on the
# host (Docker already scopes exposure), and through published-port NAT the
# bridge arrives as the Docker bridge-gateway IP, which no fixed allowlist entry
# would match. Scoped to this test image only — not a production default.
log "launching Burp Community (log: $LOG)"
yes 2>/dev/null | java \
  -XX:MaxRAMPercentage=50 \
  -Djava.awt.headless=false \
  -Djava.util.prefs.userRoot="$BURP_HOME/.java" \
  -Dburp.mcp.server.host=0.0.0.0 \
  -Dburp.mcp.server.port="$API_PORT" \
  -Dburp.mcp.allowed.hosts='*' \
  -jar "$BURP_JAR" \
  --user-config-file="$runtime_user_config" \
  --config-file="$PROJECT_CONFIG" \
  >"$LOG" 2>&1 &
BURP_PID=$!

cleanup() { kill "$BURP_PID" "$XVFB_PID" 2>/dev/null; }
trap cleanup TERM INT

# --- 3. Drive the Community project wizard --------------------------------
# Community cannot be told to skip the GUI launch dialog, so we dismiss it with
# its own defaults (Temporary project -> Next -> Start Burp). Two things make
# this reliable:
#   * Java/Swing ignores SYNTHETIC key events (xdotool --window uses XSendEvent),
#     so we focus the window and send REAL XTEST events (xdotool key, no
#     --window), and also click the primary button by geometry as a fallback.
#   * We keep nudging on a loop until the extension API answers, so it does not
#     matter which wizard page is showing or exactly when it renders.
drive_wizard_once() {
  # A stray xmessage (e.g. a JRE-version notice) can grab focus; kill it first.
  xdotool search --class xmessage windowkill 2>/dev/null
  win=$(xdotool search --name "Burp Suite Community" 2>/dev/null | head -1)
  [ -z "${win:-}" ] && return 1
  xdotool windowactivate --sync "$win" 2>/dev/null
  xdotool key --clearmodifiers Return 2>/dev/null
  # Primary button sits bottom-right of the dialog; click it by geometry too.
  local X=0 Y=0 WIDTH=0 HEIGHT=0
  eval "$(xdotool getwindowgeometry --shell "$win" 2>/dev/null)"
  if [ "${WIDTH:-0}" -gt 0 ]; then
    xdotool mousemove $((X + WIDTH - 55)) $((Y + HEIGHT - 28)) click 1 2>/dev/null
  fi
  return 0
}
wizard_loop() {
  while :; do drive_wizard_once; sleep 3; done
}
( sleep 5; wizard_loop ) &
WIZARD_PID=$!

# --- 4. Wait for the extension API, then idle -----------------------------
log "waiting for extension API on 127.0.0.1:$API_PORT"
ready=0
for _ in $(seq 1 300); do
  if ! kill -0 "$BURP_PID" 2>/dev/null; then
    kill "$WIZARD_PID" 2>/dev/null
    log "FATAL: Burp process exited early; last 40 log lines:"; tail -40 "$LOG" >&2; exit 1
  fi
  if (exec 3<>/dev/tcp/127.0.0.1/"$API_PORT") 2>/dev/null; then ready=1; break; fi
  sleep 1
done
kill "$WIZARD_PID" 2>/dev/null
if [ "$ready" != 1 ]; then
  log "FATAL: extension API never came up on $API_PORT; last 60 log lines:"; tail -60 "$LOG" >&2; exit 1
fi
log "extension API is up on $API_PORT; Burp ready"

# Surface Burp's log to `docker compose logs burp`, and keep PID 1 alive.
tail -n +1 -f "$LOG" &
wait "$BURP_PID"

#!/usr/bin/env bash
# Delete one row of Proxy > HTTP history through Burp's UI, because the Montoya
# API cannot delete proxy history and the suite needs a history with gaps.
#
#   delete-history-row.sh <row>     row = 1-based visible row, table sorted by #
#
# This drives Burp Community 2026.3.3 on this container's fixed 1280x1024 Xvfb
# display, so the coordinates below are calibrated for exactly that and nothing
# else. The caller must verify the result through the extension API (which
# entry vanished), rather than trusting the clicks. To recalibrate, screenshot
# each step: scrot /tmp/s.png, then docker compose cp burp:/tmp/s.png .
set -euo pipefail
export DISPLAY=${DISPLAY:-:99}

row=${1:?usage: delete-history-row.sh <row>}
TABLE_FIRST_ROW_Y=220   # centre of row 1 in the HTTP history table
ROW_HEIGHT=16
ROW_X=100               # inside the Host column
MENU_DELETE_DY=374      # "Delete item" sits this far below the right-click point
MENU_DELETE_X=165
YES_X=807; YES_Y=546    # "Yes" in the centred "Delete item" confirmation

win=$(xdotool search --name "Burp Suite Community" | head -1)
xdotool windowactivate --sync "$win"
xdotool mousemove 208 103 click 1; sleep 1      # Proxy tab
xdotool mousemove 144 137 click 1; sleep 1      # HTTP history sub-tab

y=$((TABLE_FIRST_ROW_Y + (row - 1) * ROW_HEIGHT))
xdotool mousemove "$ROW_X" "$y" click 1; sleep 0.5
xdotool mousemove "$ROW_X" "$y" click 3; sleep 1
xdotool mousemove "$MENU_DELETE_X" $((y + MENU_DELETE_DY)) click 1; sleep 1
xdotool mousemove "$YES_X" "$YES_Y" click 1; sleep 1

#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT="$SCRIPT_DIR/mh_tool_installer.py"

if [[ ! -f "$PY_SCRIPT" ]]; then
  echo "Missing installer script: $PY_SCRIPT" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required. Install it first: sudo apt update && sudo apt install python3" >&2
  exit 1
fi
if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for package installation." >&2
  exit 1
fi

# Ask once in this terminal; keep the sudo timestamp fresh while the GUI runs.
echo "MH Security Tool Installer needs sudo permission for APT packages."
sudo -v

# Tkinter is needed before the GUI can start, so bootstrap it from Bash if absent.
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
  echo "Tkinter is missing; installing python3-tk..."
  sudo -n apt-get update
  sudo -n apt-get install -y python3-tk
fi

( while true; do sudo -n -v >/dev/null 2>&1 || true; sleep 45; done ) &
KEEPALIVE_PID=$!
cleanup() { kill "$KEEPALIVE_PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

python3 "$PY_SCRIPT"

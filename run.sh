#!/bin/bash
set -e
cd "$(dirname "$0")"

HOST="${SENTINEL_HOST:-0.0.0.0}"
PORT="${SENTINEL_PORT:-8000}"

if command -v uvicorn >/dev/null 2>&1; then
  exec uvicorn server.app:app --app-dir src --host "$HOST" --port "$PORT"
else
  exec python3 src/server/app.py
fi

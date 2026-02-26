#!/bin/bash
# Start OWASPGuard API server. Run from anywhere.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# Activate venv if it exists
[ -f "$ROOT/.venv/bin/activate" ] && source "$ROOT/.venv/bin/activate"

PORT="${1:-8000}"
echo "Starting OWASPGuard API on http://0.0.0.0:$PORT"
exec uvicorn OWASPGuard.api.server:app --port "$PORT" --reload --host 0.0.0.0

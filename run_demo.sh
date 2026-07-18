#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "Run ./setup_kali.sh first." >&2
  exit 1
fi
source .venv/bin/activate
exec python run.py

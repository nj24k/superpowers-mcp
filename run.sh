#!/bin/bash
# Start SuperPowers: ./run.sh
cd "$(dirname "$0")"
set -a; [ -f .env ] && source .env; set +a
exec .venv/bin/python server.py "$@"

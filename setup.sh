#!/bin/bash
# SuperPowers one-command setup: ./setup.sh
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Need Python 3.10+: https://www.python.org/downloads/"
  exit 1
fi

[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt

if [ ! -f .env ]; then
  TOKEN=$(openssl rand -hex 24 2>/dev/null || python3 -c 'import secrets;print(secrets.token_hex(24))')
  echo "SUPERPOWERS_TOKEN=$TOKEN" > .env
  chmod 600 .env
  echo "Generated token (saved to .env): $TOKEN"
fi

echo ""
echo "Setup done — starting SuperPowers. Ctrl+C to stop."
echo ""
set -a; source .env; set +a
exec .venv/bin/python server.py "$@"

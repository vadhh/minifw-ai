#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=/opt/minifw_ai/app
exec /opt/minifw_ai/venv/bin/python -m minifw_ai.maintenance restore "$@"

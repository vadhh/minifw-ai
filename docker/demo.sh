#!/bin/bash
# MiniFW-AI Demo Launcher
# ──────────────────────────────────────────────────────────────
#
# Usage:
#   ./demo.sh <mode> [action]
#
# Modes:
#   hospital   HIPAA / IoMT / healthcare threats         → :8443
#   sme        SME establishment / balanced protection   → :8444
#   gambling   Regulatory gambling domain enforcement    → :8445
#   api        RitAPI Advanced API Protection WAF        → :8001
#
# Actions (default: up):
#   up     Build and start (foreground)
#   down   Stop containers
#   clean  Stop + remove volumes
#   logs   Follow logs (attach)
#   ps     Show running containers
#
# Examples:
#   ./demo.sh hospital
#   ./demo.sh sme up
#   ./demo.sh gambling down
#   ./demo.sh api logs
#
# ──────────────────────────────────────────────────────────────

set -euo pipefail

MODE="${1:-}"
ACTION="${2:-up}"

# ── Mode definitions ──────────────────────────────────────────

RITAPI_DIR="$(realpath "$(dirname "$0")/../../ritapi/ritapi-adv sc/ritapi-advanced")"

case "$MODE" in

  hospital)
    COMPOSE_FILE="docker-compose.yml"
    PRODUCT_MODE="minifw_hospital"
    URL="https://localhost:8443"
    PASSWORD="Hospital1!"
    LABEL="Hospital — HIPAA / IoMT / Healthcare Threats"
    COLOR="\033[0;31m"   # red
    ;;

  sme)
    COMPOSE_FILE="docker-compose.sme.yml"
    PRODUCT_MODE="minifw_establishment"
    URL="https://localhost:8444"
    PASSWORD="SME_Demo1!"
    LABEL="SME — Establishment / Balanced Protection"
    COLOR="\033[0;34m"   # blue
    ;;

  gambling)
    COMPOSE_FILE="docker-compose.gambling.yml"
    PRODUCT_MODE="minifw_gambling"
    URL="https://localhost:8445"
    PASSWORD="Gambling1!"
    LABEL="Gambling — Regulatory Domain Enforcement (GAMBLING_ONLY=1)"
    COLOR="\033[0;35m"   # purple
    ;;

  api)
    # RitAPI Advanced lives in a sibling project directory
    if [[ ! -f "$RITAPI_DIR/docker/demo.yml" ]]; then
      echo ""
      echo "  ERROR: RitAPI Advanced demo not found at:"
      echo "         $RITAPI_DIR/docker/demo.yml"
      echo ""
      echo "  Make sure the ritapi-advanced project is checked out at:"
      echo "  $(dirname "$RITAPI_DIR")"
      exit 1
    fi
    COMPOSE_FILE=""
    PRODUCT_MODE="ritapi_advanced"
    URL="http://localhost:8001"
    PASSWORD="(see .env.demo in ritapi-advanced)"
    LABEL="API Protection — RitAPI Advanced L7 WAF"
    COLOR="\033[0;36m"   # cyan
    ;;

  ""|--help|-h)
    echo ""
    echo "  MiniFW-AI Demo Launcher"
    echo ""
    echo "  Usage: ./demo.sh <mode> [action]"
    echo ""
    echo "  Modes:"
    printf "    %-12s %s\n" "hospital"  "HIPAA · IoMT · Healthcare          → https://localhost:8443"
    printf "    %-12s %s\n" "sme"       "SME · Balanced Protection           → https://localhost:8444"
    printf "    %-12s %s\n" "gambling"  "Regulatory · Gambling Enforcement   → https://localhost:8445"
    printf "    %-12s %s\n" "api"       "API Protection · RitAPI Advanced    → http://localhost:8001"
    echo ""
    echo "  Actions: up (default) | down | clean | logs | ps"
    echo ""
    exit 0
    ;;

  *)
    echo ""
    echo "  ERROR: Unknown mode '$MODE'"
    echo "  Run './demo.sh --help' for usage."
    echo ""
    exit 1
    ;;
esac

# ── Change to docker/ directory ───────────────────────────────

cd "$(dirname "$0")"

# ── Print header ──────────────────────────────────────────────

NC="\033[0m"
BOLD="\033[1m"

echo ""
printf "  ${BOLD}${COLOR}●  MiniFW-AI Demo — %s${NC}\n" "$LABEL"
echo "  ─────────────────────────────────────────────────────"
printf "  %-14s %s\n" "PRODUCT_MODE:" "$PRODUCT_MODE"
printf "  %-14s %s\n" "Dashboard URL:" "$URL"
printf "  %-14s %s\n" "Password:" "$PASSWORD"
printf "  %-14s %s\n" "Action:" "$ACTION"
echo ""

# ── Dispatch ──────────────────────────────────────────────────

_compose() {
  if [[ "$MODE" == "api" ]]; then
    docker compose -f "$RITAPI_DIR/docker/demo.yml" "$@"
  else
    docker compose -f "$COMPOSE_FILE" "$@"
  fi
}

case "$ACTION" in

  up)
    if [[ "$MODE" == "api" ]]; then
      echo "  Starting RitAPI Advanced demo from:"
      echo "  $RITAPI_DIR"
      echo ""
      cd "$RITAPI_DIR"
      docker compose -f docker/demo.yml up --build
    else
      _compose up --build
    fi
    ;;

  down)
    _compose down
    echo ""
    echo "  Demo stopped."
    ;;

  clean)
    _compose down -v
    echo ""
    echo "  Demo stopped and volumes removed."
    ;;

  logs)
    _compose logs -f
    ;;

  ps)
    _compose ps
    ;;

  *)
    echo "  ERROR: Unknown action '$ACTION' (use up|down|clean|logs|ps)"
    exit 1
    ;;
esac

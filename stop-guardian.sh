#!/usr/bin/env bash
# ==============================================================================
# 🛡️ GUARDIAN EDR & NDR PLATFORM — MASTER SYSTEM SHUTDOWN (Linux/Termux)
# ==============================================================================

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$SCRIPT_DIR/.guardian-pids"
QUIET="${1:-}"

if [ "$QUIET" != "--quiet" ]; then
  printf "\033[1;33m======================================================================\033[0m\n"
  printf "\033[0;31m 🛑 ENCERRANDO SISTEMA MESTRE DO GUARDIAN E SUBSISTEMAS\033[0m\n"
  printf "\033[1;33m======================================================================\033[0m\n"
fi

stop_pid_file() {
  local file="$1"
  if [ -f "$file" ]; then
    local pid
    pid="$(cat "$file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$file"
  fi
}

stop_pid_file "$PID_DIR/core.pid"
stop_pid_file "$PID_DIR/console.pid"
stop_pid_file "$PID_DIR/agent.pid"

pkill -f "$SCRIPT_DIR/guardian-core/dist/index.js" 2>/dev/null || true
pkill -f "$SCRIPT_DIR/guardian-console/node_modules/.bin/vite" 2>/dev/null || true
pkill -f "guardian_termux_agent.py" 2>/dev/null || true

if [ "$QUIET" != "--quiet" ]; then
  printf "\033[0;32m✅ Serviços Guardian encerrados.\033[0m\n"
fi

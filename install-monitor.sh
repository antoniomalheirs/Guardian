#!/usr/bin/env bash
# ==============================================================================
# 🛡️ GUARDIAN EDR — MONITOR/AGENT INSTALLER (Linux)
# ==============================================================================
set -Eeuo pipefail

SERVER_URL="${1:-${GUARDIAN_SERVER_URL:-}}"
if [ -z "$SERVER_URL" ]; then
  echo "Uso: $0 http://IP_DA_MAQUINA_MESTRE:4000" >&2
  exit 1
fi
SERVER_URL="${SERVER_URL%/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$SCRIPT_DIR/guardian-agent"
BIN_RELEASE="$AGENT_DIR/target/release/guardian-agent"
BIN_DEBUG="$AGENT_DIR/target/debug/guardian-agent"
INSTALL_DIR="$HOME/.guardian"
LOG_FILE="$INSTALL_DIR/guardian-agent.log"
PID_FILE="$INSTALL_DIR/guardian-agent.pid"

mkdir -p "$INSTALL_DIR"

if [ ! -x "$BIN_RELEASE" ] && [ ! -x "$BIN_DEBUG" ]; then
  command -v cargo >/dev/null 2>&1 || { echo "Cargo/Rust não encontrado. Instale Rust ou compile/copiei o binário guardian-agent." >&2; exit 1; }
  (cd "$AGENT_DIR" && cargo build --release)
fi

BIN="$BIN_RELEASE"
[ -x "$BIN" ] || BIN="$BIN_DEBUG"
cp "$BIN" "$INSTALL_DIR/guardian-agent"
chmod +x "$INSTALL_DIR/guardian-agent"
echo "$SERVER_URL" > "$INSTALL_DIR/server_url.txt"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
fi
nohup "$INSTALL_DIR/guardian-agent" "$SERVER_URL" > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

cat > "$INSTALL_DIR/guardian-monitor" <<'CLI'
#!/usr/bin/env bash
GUARDIAN_DIR="$HOME/.guardian"
PID_FILE="$GUARDIAN_DIR/guardian-agent.pid"
LOG_FILE="$GUARDIAN_DIR/guardian-agent.log"
SERVER_URL="$(cat "$GUARDIAN_DIR/server_url.txt" 2>/dev/null || echo http://localhost:4000)"
case "$1" in
  start) nohup "$GUARDIAN_DIR/guardian-agent" "$SERVER_URL" > "$LOG_FILE" 2>&1 & echo $! > "$PID_FILE"; echo "Guardian monitor iniciado." ;;
  stop) [ -f "$PID_FILE" ] && kill "$(cat "$PID_FILE")" 2>/dev/null || true; rm -f "$PID_FILE"; echo "Guardian monitor parado." ;;
  restart) "$0" stop; sleep 1; "$0" start ;;
  status) [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null && echo "Ativo (PID $(cat "$PID_FILE"))" || echo "Inativo" ;;
  logs) touch "$LOG_FILE"; tail -n 80 -f "$LOG_FILE" ;;
  *) echo "Uso: guardian-monitor {start|stop|restart|status|logs}" ;;
esac
CLI
chmod +x "$INSTALL_DIR/guardian-monitor"
mkdir -p "$HOME/bin"
ln -sf "$INSTALL_DIR/guardian-monitor" "$HOME/bin/guardian-monitor"

echo "✅ Monitor Linux instalado e iniciado contra $SERVER_URL"
echo "Controle: $HOME/bin/guardian-monitor {status|logs|restart|stop}"

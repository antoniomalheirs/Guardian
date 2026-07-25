#!/usr/bin/env bash
# ==============================================================================
# 🛡️ GUARDIAN EDR & NDR PLATFORM — MASTER SYSTEM LAUNCHER (Linux/Termux)
# ==============================================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/guardian-core"
CONSOLE_DIR="$SCRIPT_DIR/guardian-console"
AGENT_DIR="$SCRIPT_DIR/guardian-agent"
PID_DIR="$SCRIPT_DIR/.guardian-pids"
LOG_DIR="$SCRIPT_DIR/.guardian-logs"
CORE_PID_FILE="$PID_DIR/core.pid"
CONSOLE_PID_FILE="$PID_DIR/console.pid"
AGENT_PID_FILE="$PID_DIR/agent.pid"
API_PORT="${GUARDIAN_API_PORT:-4000}"
CONSOLE_PORT="${GUARDIAN_CONSOLE_PORT:-4001}"
SECRETS_FILE="$SCRIPT_DIR/.guardian-secrets.env"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

mkdir -p "$PID_DIR" "$LOG_DIR"
cd "$SCRIPT_DIR"

is_termux() { [ -d "/data/data/com.termux" ] || [ -n "${TERMUX_VERSION:-}" ]; }

get_local_ip() {
  if command -v ip >/dev/null 2>&1; then
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
  elif command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | awk '{print $1}'
  fi
}


require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf "${RED}[ERRO] Comando obrigatório não encontrado: %s${NC}\n" "$1" >&2
    exit 1
  fi
}

wait_for_http() {
  local url="$1" retries="${2:-30}"
  for _ in $(seq 1 "$retries"); do
    if command -v curl >/dev/null 2>&1 && curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    printf "."; sleep 1
  done
  return 1
}

LOCAL_IP="$(get_local_ip || true)"
LOCAL_IP="${LOCAL_IP:-localhost}"
SERVER_URL="${GUARDIAN_SERVER_URL:-http://$LOCAL_IP:$API_PORT}"

printf "${CYAN}======================================================================${NC}\n"
printf "${GREEN} 🛡️ INICIALIZANDO GUARDIAN EDR & NDR MASTER SYSTEM (%s)${NC}\n" "$LOCAL_IP"
printf "${CYAN}======================================================================${NC}\n\n"

printf "${YELLOW}[1/5] Encerrando instâncias Guardian anteriores...${NC}\n"
"$SCRIPT_DIR/stop-guardian.sh" --quiet 2>/dev/null || true
pkill -f "$CORE_DIR/dist/index.js" 2>/dev/null || true
pkill -f "$CONSOLE_DIR/node_modules/.bin/vite" 2>/dev/null || true
pkill -f "guardian_termux_agent.py" 2>/dev/null || true

printf "${YELLOW}[2/5] Verificando dependências Node.js/npm...${NC}\n"
require_cmd node
require_cmd npm
if is_termux; then
  command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1 || printf "       ${YELLOW}[INFO] Python não encontrado; agente local Termux não será iniciado.${NC}\n"
fi

for dir in "$CORE_DIR" "$CONSOLE_DIR"; do
  if [ ! -d "$dir/node_modules" ]; then
    printf "       Instalando dependências em %s...\n" "$(basename "$dir")"
    (cd "$dir" && npm ci)
  fi
done

printf "${YELLOW}[3/5] Compilando Core API e Console Web...${NC}\n"
(cd "$CORE_DIR" && npm run build)
(cd "$CONSOLE_DIR" && VITE_GUARDIAN_API_URL="$SERVER_URL" npm run build)
printf "       ${GREEN}✓ Builds concluídos.${NC}\n"

printf "${YELLOW}[4/5] Subindo API (%s) e Dashboard (%s)...${NC}\n" "$API_PORT" "$CONSOLE_PORT"
( cd "$CORE_DIR" && PORT="$API_PORT" nohup node dist/index.js > "$LOG_DIR/core.log" 2>&1 & echo $! > "$CORE_PID_FILE" )
( cd "$CONSOLE_DIR" && VITE_GUARDIAN_API_URL="$SERVER_URL" nohup npm run dev -- --host 0.0.0.0 --port "$CONSOLE_PORT" > "$LOG_DIR/console.log" 2>&1 & echo $! > "$CONSOLE_PID_FILE" )

printf "${YELLOW}[5/5] Iniciando agente local quando disponível...${NC}\n"
if is_termux; then
  PYTHON_BIN="$(command -v python || command -v python3 || true)"
  if [ -n "$PYTHON_BIN" ] && [ -f "$AGENT_DIR/guardian_termux_agent.py" ]; then
    nohup "$PYTHON_BIN" "$AGENT_DIR/guardian_termux_agent.py" "$SERVER_URL" > "$LOG_DIR/agent.log" 2>&1 & echo $! > "$AGENT_PID_FILE"
    printf "       ${GREEN}✓ Agente Python Termux iniciado contra %s.${NC}\n" "$SERVER_URL"
  fi
else
  if [ -x "$AGENT_DIR/target/release/guardian-agent" ]; then
    nohup "$AGENT_DIR/target/release/guardian-agent" "$SERVER_URL" > "$LOG_DIR/agent.log" 2>&1 & echo $! > "$AGENT_PID_FILE"
    printf "       ${GREEN}✓ Agente Rust Linux iniciado contra %s.${NC}\n" "$SERVER_URL"
  elif [ -x "$AGENT_DIR/target/debug/guardian-agent" ]; then
    nohup "$AGENT_DIR/target/debug/guardian-agent" "$SERVER_URL" > "$LOG_DIR/agent.log" 2>&1 & echo $! > "$AGENT_PID_FILE"
    printf "       ${GREEN}✓ Agente Rust Linux (debug) iniciado contra %s.${NC}\n" "$SERVER_URL"
  else
    printf "       ${YELLOW}[INFO] Agente Rust não compilado. Para ativar: cd guardian-agent && cargo build --release${NC}\n"
  fi
fi

printf "\n       Aguardando API Mestre"
if wait_for_http "http://localhost:$API_PORT/api/v1/health" 30; then
  printf "\n       ${GREEN}✓ Servidor API respondendo na porta %s.${NC}\n" "$API_PORT"
else
  printf "\n       ${YELLOW}[AVISO] API ainda inicializando. Veja %s/core.log${NC}\n" "$LOG_DIR"
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:$CONSOLE_PORT" >/dev/null 2>&1 || true
fi

printf "\n${GREEN}======================================================================${NC}\n"
printf "${GREEN} ✅ SISTEMA MESTRE GUARDIAN EDR & NDR ATIVADO!${NC}\n"
printf "${GREEN}======================================================================${NC}\n"
printf "${CYAN} 🌐 Dashboard Web:       http://localhost:%s${NC}\n" "$CONSOLE_PORT"
printf "${CYAN} 🌐 Dashboard Rede:      http://%s:%s${NC}\n" "$LOCAL_IP" "$CONSOLE_PORT"
printf "${CYAN} 🛡️ API Core Server:    %s${NC}\n" "$SERVER_URL"
printf "${CYAN} 📄 Logs:                %s${NC}\n" "$LOG_DIR"
printf "${YELLOW} 📱 Termux Android:      pkg install -y curl bash && curl -sSL '%s/android.sh' | bash${NC}\n" "$SERVER_URL"
printf "${GREEN}======================================================================${NC}\n"

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
CORE_PID_FILE="$PID_DIR/core.pid"
CONSOLE_PID_FILE="$PID_DIR/console.pid"
AGENT_PID_FILE="$PID_DIR/agent.pid"
LOG_DIR="$SCRIPT_DIR/.guardian-logs"

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

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${RED}[ERRO] Comando obrigatório não encontrado: $1${NC}" >&2
    exit 1
  fi
}

LOCAL_IP="$(get_local_ip || true)"
LOCAL_IP="${LOCAL_IP:-localhost}"

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

for dir in "$CORE_DIR" "$CONSOLE_DIR"; do
  if [ ! -d "$dir/node_modules" ]; then
    printf "       Instalando dependências em %s...\n" "$(basename "$dir")"
    (cd "$dir" && npm ci)
  fi
done

printf "${YELLOW}[3/5] Compilando Core API e Console Web...${NC}\n"
(cd "$CORE_DIR" && npm run build)
(cd "$CONSOLE_DIR" && npm run build)
printf "       ${GREEN}✓ Builds concluídos.${NC}\n"

printf "${YELLOW}[4/5] Subindo API (4000) e Dashboard (4001)...${NC}\n"
( cd "$CORE_DIR" && PORT=4000 nohup node dist/index.js > "$LOG_DIR/core.log" 2>&1 & echo $! > "$CORE_PID_FILE" )
( cd "$CONSOLE_DIR" && nohup npm run dev -- --host 0.0.0.0 > "$LOG_DIR/console.log" 2>&1 & echo $! > "$CONSOLE_PID_FILE" )

printf "${YELLOW}[5/5] Iniciando agente local quando disponível...${NC}\n"
if is_termux; then
  if [ -f "$AGENT_DIR/guardian_termux_agent.py" ]; then
    nohup python "$AGENT_DIR/guardian_termux_agent.py" "http://$LOCAL_IP:4000" > "$LOG_DIR/agent.log" 2>&1 & echo $! > "$AGENT_PID_FILE"
    printf "       ${GREEN}✓ Agente Python Termux iniciado.${NC}\n"
  fi
else
  if [ -x "$AGENT_DIR/target/release/guardian-agent" ]; then
    nohup "$AGENT_DIR/target/release/guardian-agent" > "$LOG_DIR/agent.log" 2>&1 & echo $! > "$AGENT_PID_FILE"
    printf "       ${GREEN}✓ Agente Rust Linux iniciado.${NC}\n"
  elif [ -x "$AGENT_DIR/target/debug/guardian-agent" ]; then
    nohup "$AGENT_DIR/target/debug/guardian-agent" > "$LOG_DIR/agent.log" 2>&1 & echo $! > "$AGENT_PID_FILE"
    printf "       ${GREEN}✓ Agente Rust Linux (debug) iniciado.${NC}\n"
  else
    printf "       ${YELLOW}[INFO] Agente Rust não compilado. Para ativar: cd guardian-agent && cargo build --release${NC}\n"
  fi
fi

printf "\n       Aguardando API Mestre"
healthy=false
for _ in $(seq 1 20); do
  if command -v curl >/dev/null 2>&1 && curl -fsS "http://localhost:4000/api/v1/health" >/dev/null 2>&1; then
    healthy=true; break
  fi
  printf "."; sleep 1
done
printf "\n"

if [ "$healthy" = true ]; then
  printf "       ${GREEN}✓ Servidor API respondendo na porta 4000.${NC}\n"
else
  printf "       ${YELLOW}[AVISO] API ainda inicializando. Veja $LOG_DIR/core.log${NC}\n"
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://localhost:4001" >/dev/null 2>&1 || true
fi

printf "\n${GREEN}======================================================================${NC}\n"
printf "${GREEN} ✅ SISTEMA MESTRE GUARDIAN EDR & NDR ATIVADO!${NC}\n"
printf "${GREEN}======================================================================${NC}\n"
printf "${CYAN} 🌐 Dashboard Web:       http://localhost:4001${NC}\n"
printf "${CYAN} 🌐 Dashboard Rede:      http://%s:4001${NC}\n" "$LOCAL_IP"
printf "${CYAN} 🛡️ API Core Server:    http://%s:4000${NC}\n" "$LOCAL_IP"
printf "${CYAN} 📄 Logs:                %s${NC}\n" "$LOG_DIR"
printf "${YELLOW} 📱 Termux Android:      pkg install -y curl bash && curl -sSL http://%s:4000/android.sh | bash${NC}\n" "$LOCAL_IP"
printf "${GREEN}======================================================================${NC}\n"

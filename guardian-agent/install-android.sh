#!/usr/bin/env bash
# ==============================================================================
# 🛡️ GUARDIAN EDR — SCRIPT DE INSTALAÇÃO AUTOMÁTICA PARA ANDROID (TERMUX)
# ==============================================================================
# Instalação completa de dependências, agente de segurança e daemon em 1-clique.
# ==============================================================================

set -Eeuo pipefail

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "======================================================================"
echo " 🛡️ GUARDIAN EDR — ANDROID / TERMUX AUTOMATED INSTALLER"
echo "======================================================================"
echo -e "${NC}"

# 1. Detectar Servidor Mestre (Extraído da URL de Download ou Argumento)
DEFAULT_SERVER="${GUARDIAN_SERVER:-http://192.168.50.140:4000}"
if [ -n "${1:-}" ]; then
    SERVER_URL="$1"
else
    SERVER_URL="$DEFAULT_SERVER"
fi
SERVER_URL="${SERVER_URL%/}"
DOWNLOAD_TOKEN="${GUARDIAN_DOWNLOAD_TOKEN:-${GUARDIAN_ADMIN_TOKEN:-}}"
AGENT_TOKEN="${GUARDIAN_AGENT_TOKEN:-}"
append_token() {
    local url="$1"
    if [ -n "$DOWNLOAD_TOKEN" ]; then
        printf "%s?token=%s" "$url" "$DOWNLOAD_TOKEN"
    else
        printf "%s" "$url"
    fi
}

echo -e "${YELLOW}[1/6] Verificando ambiente de execução...${NC}"
IS_TERMUX=false
if [ -d "/data/data/com.termux" ] || [ -n "${TERMUX_VERSION:-}" ]; then
    IS_TERMUX=true
    echo -e "       ${GREEN}✓ Ambiente Termux Android detectado.${NC}"
else
    echo -e "       ${GREEN}✓ Ambiente Linux Genérico detectado.${NC}"
fi

# Solicitando acesso a armazenamento se estiver no Termux
if [ "$IS_TERMUX" = true ] && command -v termux-setup-storage >/dev/null 2>&1; then
    echo -e "       Configurando armazenamento do Termux..."
    termux-setup-storage 2>/dev/null || true
fi

# 2. Atualização e Instalação de Pacotes
echo -e "\n${YELLOW}[2/6] Instalando dependências de sistema (Python, Curl, Tools)...${NC}"
if [ "$IS_TERMUX" = true ]; then
    pkg update -y || true
    pkg install -y python curl procps android-tools iproute2 util-linux coreutils >/dev/null 2>&1 || {
        echo -e "       ${YELLOW}Instalação alternativa de pacotes...${NC}"
        pkg install -y python curl || true
    }
else
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y && sudo apt-get install -y python3 python3-pip curl procps >/dev/null 2>&1 || true
    fi
fi
echo -e "       ${GREEN}✓ Dependências instaladas com sucesso.${NC}"

# 3. Criar Diretório de Trabalho do Agente Guardian
echo -e "\n${YELLOW}[3/6] Configurando diretório ~/.guardian...${NC}"
GUARDIAN_DIR="$HOME/.guardian"
mkdir -p "$GUARDIAN_DIR"
mkdir -p "$HOME/bin"

AGENT_FILE="$GUARDIAN_DIR/guardian_termux_agent.py"

# 4. Download do Agente Python Atualizado
echo -e "\n${YELLOW}[4/6] Baixando agente Guardian mais recente de ${SERVER_URL}...${NC}"
AGENT_DOWNLOAD_URL="$(append_token "${SERVER_URL}/download/agent.py")"

if command -v curl >/dev/null 2>&1; then
    curl -sSL "$AGENT_DOWNLOAD_URL" -o "$AGENT_FILE"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$AGENT_DOWNLOAD_URL" -O "$AGENT_FILE"
else
    echo -e "${RED}[ERRO CRÍTICO] Nem curl nem wget encontrados!${NC}"
    exit 1
fi

if [ ! -s "$AGENT_FILE" ]; then
    echo -e "${RED}[ERRO CRÍTICO] Falha ao baixar agente de $AGENT_DOWNLOAD_URL${NC}"
    exit 1
fi

echo -e "       ${GREEN}✓ Agente salvo em $AGENT_FILE${NC}"
echo "$SERVER_URL" > "$GUARDIAN_DIR/server_url.txt"
if [ -n "$AGENT_TOKEN" ]; then
    umask 077
    printf "%s" "$AGENT_TOKEN" > "$GUARDIAN_DIR/agent_token.txt"
    echo -e "       ${GREEN}✓ Token do agente salvo com permissões restritas.${NC}"
fi
echo -e "       ${GREEN}✓ Servidor Mestre salvo: $SERVER_URL${NC}"

# 5. Criar Atalho Global / Binário 'guardian'
echo -e "\n${YELLOW}[5/6] Criando atalho global de controle ('guardian')...${NC}"

CLI_BIN="$HOME/bin/guardian"
cat << 'EOF' > "$CLI_BIN"
#!/usr/bin/env bash
GUARDIAN_DIR="$HOME/.guardian"
AGENT_FILE="$GUARDIAN_DIR/guardian_termux_agent.py"
PID_FILE="$GUARDIAN_DIR/guardian.pid"
LOG_FILE="$GUARDIAN_DIR/guardian.log"
SERVER_FILE="$GUARDIAN_DIR/server_url.txt"
AGENT_TOKEN_FILE="$GUARDIAN_DIR/agent_token.txt"

SERVER_URL=""
if [ -f "$SERVER_FILE" ]; then
    SERVER_URL=$(cat "$SERVER_FILE")
fi
if [ -f "$AGENT_TOKEN_FILE" ]; then
    export GUARDIAN_AGENT_TOKEN="$(cat "$AGENT_TOKEN_FILE")"
fi

case "$1" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "⚠️ Guardian Agente já está rodando (PID: $(cat $PID_FILE))."
        else
            echo "🚀 Iniciando Guardian Agente em segundo plano (Daemon)..."
            if command -v termux-wake-lock >/dev/null 2>&1; then
                termux-wake-lock
            fi
            PYTHON_BIN="$(command -v python || command -v python3 || true)"
            if [ -z "$PYTHON_BIN" ]; then
                echo "❌ Python não encontrado. Instale com: pkg install python"
                exit 1
            fi
            if command -v su >/dev/null 2>&1 && su -c 'id -u' 2>/dev/null | grep -qx '0'; then
                echo "🔓 Root detectado: o agente usará su -c para telemetria profunda de processos e sockets."
            fi
            nohup "$PYTHON_BIN" "$AGENT_FILE" "$SERVER_URL" > "$LOG_FILE" 2>&1 &
            echo $! > "$PID_FILE"
            echo "✅ Agente iniciado com sucesso! PID: $(cat $PID_FILE)"
        fi
        ;;
    stop)
        echo "🛑 Parando instâncias anteriores do Guardian Agente..."
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            kill -9 "$PID" 2>/dev/null || true
            rm -f "$PID_FILE"
        fi
        pkill -f guardian_termux_agent.py 2>/dev/null || true
        pkill -f agent.py 2>/dev/null || true
        if command -v termux-wake-unlock >/dev/null 2>&1; then
            termux-wake-unlock 2>/dev/null || true
        fi
        echo "✅ Agente parado."
        ;;
    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "🟢 Guardian Agente está ATIVO (PID: $(cat $PID_FILE))."
        else
            echo "🔴 Guardian Agente está INATIVO."
        fi
        if command -v su >/dev/null 2>&1 && su -c 'id -u' 2>/dev/null | grep -qx '0'; then
            echo "🔓 Root disponível: telemetria profunda habilitada."
        else
            echo "🔒 Root não disponível/autorizado: usando modo Android sem root."
        fi
        ;;
    update)
        if [ -z "$SERVER_URL" ]; then
            echo "❌ URL do servidor não encontrada em $SERVER_FILE"
            exit 1
        fi
        echo "⬇️ Baixando agente atualizado de $SERVER_URL/download/agent.py ..."
        if command -v curl >/dev/null 2>&1; then
            curl -sSL "${SERVER_URL}/download/agent.py${GUARDIAN_DOWNLOAD_TOKEN:+?token=$GUARDIAN_DOWNLOAD_TOKEN}" -o "$AGENT_FILE"
        elif command -v wget >/dev/null 2>&1; then
            wget -q "${SERVER_URL}/download/agent.py${GUARDIAN_DOWNLOAD_TOKEN:+?token=$GUARDIAN_DOWNLOAD_TOKEN}" -O "$AGENT_FILE"
        else
            echo "❌ curl/wget não encontrado."
            exit 1
        fi
        chmod +x "$AGENT_FILE" 2>/dev/null || true
        echo "✅ Agente atualizado. Reiniciando..."
        $0 restart
        ;;
    log|logs)
        touch "$LOG_FILE"
        tail -n 50 -f "$LOG_FILE"
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    *)
        echo "Uso: guardian {start|stop|restart|status|logs|update}"
        ;;
esac
EOF

chmod +x "$CLI_BIN"

# Copiar para $PREFIX/bin (pasta nativa de executáveis do Termux) para acesso global imediato
if [ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ]; then
    cp "$CLI_BIN" "$PREFIX/bin/guardian" 2>/dev/null || true
    chmod +x "$PREFIX/bin/guardian" 2>/dev/null || true
fi

# Adicionar ~/bin ao PATH em .bashrc e .zshrc por garantia
if [ -f "$HOME/.bashrc" ]; then
    grep -q "HOME/bin" "$HOME/.bashrc" || echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.bashrc"
fi
if [ -f "$HOME/.zshrc" ]; then
    grep -q "HOME/bin" "$HOME/.zshrc" || echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.zshrc"
fi

# 6. Iniciar Agente Imediatamente (Reiniciando instâncias anteriores)
echo -e "\n${YELLOW}[6/6] Ativando Guardian Agente em segundo plano...${NC}"
"$CLI_BIN" restart

echo -e "\n${CYAN}======================================================================${NC}"
echo -e "${GREEN} ✅ INSTALAÇÃO DO GUARDIAN ANDROID CONCLUÍDA COM SUCESSO!${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo -e " 📍 Agente instalado em: $AGENT_FILE"
echo -e " ⚡ Para controlar o agente a qualquer momento:"
echo -e "    ${YELLOW}guardian status${NC}  (Verifica o status)"
echo -e "    ${YELLOW}guardian logs${NC}    (Acompanha os logs em tempo real)"
echo -e "    ${YELLOW}guardian stop${NC}    (Encerra o agente)"
echo -e "    ${YELLOW}guardian start${NC}   (Inicia o agente)"
echo -e "${CYAN}======================================================================${NC}\n"

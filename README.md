# Guardian EDR Platform 🛡️

O **Guardian EDR** é uma plataforma modular de *Endpoint Detection and Response* (EDR) para inventário, telemetria, detecção de ameaças e resposta automatizada. O repositório inclui uma **máquina mestre** (API + dashboard) e **monitores/agentes** para os demais dispositivos.

---

## 🏗️ Arquitetura do Monorepositório

```text
Guardian/
├── start-guardian.sh       # Inicializa a máquina mestre no Linux/Termux
├── start-guardian.ps1      # Inicializa a máquina mestre no Windows PowerShell
├── install-monitor.sh      # Instala/inicia monitor Linux em dispositivo cliente
├── install-monitor.ps1     # Instala/inicia monitor Windows em dispositivo cliente
├── guardian-agent/         # Agente Rust e instalador Android/Termux
├── guardian-core/          # Servidor central API Node/TypeScript (porta 4000)
├── guardian-console/       # Dashboard React + Vite (porta 4001)
└── docs/                   # Documentação técnica por volumes
```

---

## 🚀 Componentes

### Máquina mestre
- **Guardian Core API:** recebe cadastro, heartbeat e telemetria dos agentes em `http://IP_MESTRE:4000`.
- **Guardian Console:** painel web em `http://IP_MESTRE:4001`.
- **Banco local:** SQLite em `guardian-core/guardian.db`.

### Monitores/agentes
- **Windows/Linux:** agente Rust (`guardian-agent`) executado contra a URL da máquina mestre.
- **Android/Termux:** agente Python instalado via `android.sh`, baixado diretamente do Core.

---

## 📋 Pré-requisitos

### Máquina mestre Linux
- Node.js e npm no `PATH`.
- Bash, curl e ferramentas básicas do sistema.
- Opcional: Rust/Cargo se quiser compilar e rodar também o agente local Rust.

### Máquina mestre Windows
- Node.js e npm no `PATH`.
- PowerShell 5.1+ ou PowerShell 7+.
- Opcional: Rust/Cargo se quiser compilar e rodar também o agente local Rust.

### Android/Termux
- Aplicativo Termux instalado.
- Dispositivo na mesma rede da máquina mestre ou com rota/VPN até ela.

---

## 🖥️ Instalação da máquina mestre

> Execute a máquina mestre primeiro. Ela mostra no final os endereços corretos para o dashboard, API e instalação dos monitores Android.

### Linux

```bash
cd Guardian
chmod +x start-guardian.sh stop-guardian.sh install-monitor.sh
./start-guardian.sh
```

### Windows

```powershell
cd Guardian
powershell -ExecutionPolicy Bypass -File .\start-guardian.ps1
```

Ou use o atalho:

```bat
start-guardian.bat
```

### Portas personalizadas

Por padrão, a API usa `4000` e o console usa `4001`. Para mudar:

```bash
GUARDIAN_API_PORT=5000 GUARDIAN_CONSOLE_PORT=5001 ./start-guardian.sh
```

```powershell
$env:GUARDIAN_API_PORT="5000"
$env:GUARDIAN_CONSOLE_PORT="5001"
.\start-guardian.ps1
```

### Verificação rápida

```bash
curl http://localhost:4000/api/v1/health
```

Acesse o dashboard em:

```text
http://localhost:4001
http://IP_DA_MAQUINA_MESTRE:4001
```

---

## 📡 Instalação dos monitores nos demais dispositivos

Substitua `IP_DA_MAQUINA_MESTRE` pelo IP exibido pelo script de inicialização da máquina mestre.

### Monitor Android / Termux

No Termux do telefone/tablet:

```bash
pkg install -y curl bash
curl -sSL http://IP_DA_MAQUINA_MESTRE:4000/android.sh | bash
```

Controle do agente no Android:

```bash
guardian status
guardian logs
guardian restart
guardian stop
```

### Monitor Linux

No dispositivo Linux cliente, com este repositório disponível:

```bash
cd Guardian
chmod +x install-monitor.sh
./install-monitor.sh http://IP_DA_MAQUINA_MESTRE:4000
```

Controle do monitor Linux:

```bash
~/bin/guardian-monitor status
~/bin/guardian-monitor logs
~/bin/guardian-monitor restart
~/bin/guardian-monitor stop
```

### Monitor Windows

No dispositivo Windows cliente, com este repositório disponível:

```powershell
cd Guardian
powershell -ExecutionPolicy Bypass -File .\install-monitor.ps1 -ServerUrl http://IP_DA_MAQUINA_MESTRE:4000
```

Controle do monitor Windows:

```powershell
powershell -ExecutionPolicy Bypass -File $env:USERPROFILE\.guardian\guardian-monitor.ps1 status
powershell -ExecutionPolicy Bypass -File $env:USERPROFILE\.guardian\guardian-monitor.ps1 logs
powershell -ExecutionPolicy Bypass -File $env:USERPROFILE\.guardian\guardian-monitor.ps1 restart
powershell -ExecutionPolicy Bypass -File $env:USERPROFILE\.guardian\guardian-monitor.ps1 stop
```

---

## 🛑 Encerramento da máquina mestre

### Linux

```bash
./stop-guardian.sh
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\stop-guardian.ps1
```

---

## 🔧 Observações importantes

- Libere as portas `4000/TCP` e `4001/TCP` no firewall da máquina mestre.
- Todos os monitores devem apontar para a URL da API mestre, por exemplo `http://192.168.1.10:4000`.
- Os scripts de inicialização instalam dependências Node com `npm ci` quando `node_modules` não existe, compilam Core/Console e iniciam os serviços em segundo plano.
- Logs da máquina mestre ficam em `.guardian-logs/`.
- Logs dos monitores Linux/Windows ficam em `~/.guardian/` ou `%USERPROFILE%\.guardian\`.

---

## 💻 Licença

Desenvolvido como projeto de engenharia de segurança de sistemas.

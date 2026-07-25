# ==============================================================================
# 🛡️ GUARDIAN EDR & NDR PLATFORM — MASTER SYSTEM LAUNCHER (v12.0.0)
# ==============================================================================
# Script de Inicialização Automática da Máquina Mestre e Subsistemas
# ==============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

# 0. Detect Dynamic Host IP Address
$LocalIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
    $_.InterfaceAlias -notlike "*Loopback*" -and 
    $_.IPAddress -notlike "127.*" -and 
    $_.IPAddress -notlike "169.*" -and
    $_.IPAddress -notlike "172.17.*" -and
    $_.IPAddress -notlike "172.18.*"
} | Select-Object -First 1).IPAddress

if (-not $LocalIP) { $LocalIP = "localhost" }

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " 🛡️ INICIALIZANDO GUARDIAN EDR & NDR MASTER SYSTEM ($LocalIP)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Finalizar apenas processos Guardian anteriores (preservando outros servidores Node)
Write-Host "[1/5] Encerrando instâncias Guardian anteriores em execução..." -ForegroundColor Yellow
Get-Process -Name "guardian-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Terminar subprocessos Node do guardian-core e vite
Get-WmiObject Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object { 
    $_.CommandLine -like "*guardian-core*" -or $_.CommandLine -like "*guardian-console*"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Start-Sleep -Seconds 1

# 2. Compilar Guardian Core API (TypeScript)
Write-Host "[2/5] Compilando Guardian Core API (Backend TypeScript)..." -ForegroundColor Yellow
Set-Location "$ScriptDir\guardian-core"
$buildCore = & npm run build 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERRO CRÍTICO] Falha ao compilar Guardian Core API:" -ForegroundColor Red
    Write-Host $buildCore -ForegroundColor Red
    exit 1
}
Write-Host "       Guardian Core API compilado com sucesso." -ForegroundColor Green

# 3. Compilar Guardian Console Web (React/Vite)
Write-Host "[3/5] Compilando Guardian Console Web (Frontend)..." -ForegroundColor Yellow
Set-Location "$ScriptDir\guardian-console"
$buildConsole = & npm run build 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[AVISO] Falha no build de produção do Console. Usando modo Dev Vite..." -ForegroundColor Yellow
} else {
    Write-Host "       Guardian Console Web verificado e compilado." -ForegroundColor Green
}

# 4. Iniciar Servidor Mestre e Dashboard Web
Write-Host "[4/5] Subindo Servidor API (Porta 4000) e Dashboard Console (Porta 4001)..." -ForegroundColor Yellow
Start-Process node -ArgumentList "`"$ScriptDir\guardian-core\dist\index.js`"" -WorkingDirectory "$ScriptDir\guardian-core" -WindowStyle Hidden
Start-Process cmd.exe -ArgumentList "/c", "npm", "--prefix", "`"$ScriptDir\guardian-console`"", "run", "dev" -WorkingDirectory "$ScriptDir\guardian-console" -WindowStyle Hidden

# 5. Iniciar Agente EDR Local (Rust Agent para Windows)
Write-Host "[5/5] Iniciando Agente EDR Local (Rust Windows Agent)..." -ForegroundColor Yellow
$ReleaseAgent = "$ScriptDir\guardian-agent\target\release\guardian-agent.exe"
$DebugAgent = "$ScriptDir\guardian-agent\target\debug\guardian-agent.exe"

if (Test-Path $ReleaseAgent) {
    Start-Process $ReleaseAgent -WorkingDirectory "$ScriptDir\guardian-agent" -WindowStyle Hidden
    Write-Host "       Agente EDR Windows (Release) iniciado." -ForegroundColor Green
} elseif (Test-Path $DebugAgent) {
    Start-Process $DebugAgent -WorkingDirectory "$ScriptDir\guardian-agent" -WindowStyle Hidden
    Write-Host "       Agente EDR Windows (Debug) iniciado." -ForegroundColor Green
} else {
    Write-Host "       [INFO] Agente Rust Windows não compilado. Para ativar: cd guardian-agent; cargo build --release" -ForegroundColor Yellow
}

# Aguardar verificações de saúde do servidor
Write-Host ""
Write-Host "       Aguardando inicialização da API Mestre..." -ForegroundColor DarkGray
$retries = 0
$healthy = $false
while ($retries -lt 12) {
    try {
        $res = Invoke-WebRequest -Uri "http://localhost:4000/api/v1/health" -TimeoutSec 2 -ErrorAction Stop
        if ($res.StatusCode -eq 200) {
            $healthy = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
        $retries++
    }
}

if ($healthy) {
    Write-Host "       Servidor API respondendo com sucesso na porta 4000!" -ForegroundColor Green
} else {
    Write-Host "       [AVISO] Servidor ainda está inicializando..." -ForegroundColor Yellow
}

# Abrir o Dashboard no Navegador Padrão
Start-Process "http://localhost:4001"

$dbPath = "$ScriptDir\guardian-core\guardian.db"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " ✅ SISTEMA MESTRE GUARDIAN EDR & NDR ATIVADO E RODANDO!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " 🌐 Dashboard Web:         http://localhost:4001" -ForegroundColor Cyan
Write-Host " 🌐 Dashboard Rede Local:   http://${LocalIP}:4001" -ForegroundColor Cyan
Write-Host " 🛡️ API Core Server:      http://${LocalIP}:4000" -ForegroundColor Cyan
Write-Host " 🗄️ Banco de Dados:        SQLite ($dbPath)" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host " 📱 COMANDO DE INSTALAÇÃO AUTOMÁTICA NO ANDROID (TERMUX):" -ForegroundColor Yellow
Write-Host "    pkg install -y curl bash && curl -sSL http://${LocalIP}:4000/android.sh | bash" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

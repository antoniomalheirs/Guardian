# ==============================================================================
# 🛡️ GUARDIAN EDR & NDR PLATFORM — MASTER SYSTEM LAUNCHER (v12.0.0)
# ==============================================================================
# Script de Inicialização Automática da Máquina Mestre e Subsistemas
# ==============================================================================

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir
$ApiPort = if ($env:GUARDIAN_API_PORT) { $env:GUARDIAN_API_PORT } else { "4000" }
$ConsolePort = if ($env:GUARDIAN_CONSOLE_PORT) { $env:GUARDIAN_CONSOLE_PORT } else { "4001" }
$SecretsFile = Join-Path $ScriptDir ".guardian-secrets.ps1"


# 0. Detect Dynamic Host IP Address
$LocalIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.InterfaceAlias -notlike "*Loopback*" -and
    $_.IPAddress -notlike "127.*" -and
    $_.IPAddress -notlike "169.*" -and
    $_.IPAddress -notlike "172.17.*" -and
    $_.IPAddress -notlike "172.18.*"
} | Select-Object -First 1).IPAddress

if (-not $LocalIP) { $LocalIP = "localhost" }
$ServerUrl = if ($env:GUARDIAN_SERVER_URL) { $env:GUARDIAN_SERVER_URL.TrimEnd("/") } else { "http://${LocalIP}:${ApiPort}" }

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " 🛡️ INICIALIZANDO GUARDIAN EDR & NDR MASTER SYSTEM ($LocalIP)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Finalizar apenas processos Guardian anteriores (preservando outros servidores Node)
Write-Host "[1/5] Encerrando instâncias Guardian anteriores em execução..." -ForegroundColor Yellow
Get-Process -Name "guardian-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Terminar subprocessos Node do guardian-core e vite
Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*guardian-core*" -or $_.CommandLine -like "*guardian-console*"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Start-Sleep -Seconds 1

# Validar dependências essenciais
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERRO CRÍTICO] Node.js não encontrado no PATH." -ForegroundColor Red
    exit 1
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "[ERRO CRÍTICO] npm não encontrado no PATH." -ForegroundColor Red
    exit 1
}


# Instalar dependências quando node_modules ainda não existe
foreach ($Project in @("guardian-core", "guardian-console")) {
    $ProjectDir = Join-Path $ScriptDir $Project
    if (-not (Test-Path (Join-Path $ProjectDir "node_modules"))) {
        Write-Host "       Instalando dependências em $Project..." -ForegroundColor Yellow
        Push-Location $ProjectDir
        & npm ci
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERRO CRÍTICO] Falha ao instalar dependências em $Project." -ForegroundColor Red
            Pop-Location
            exit 1
        }
        Pop-Location
    }
}

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
$previousViteApiUrl = $env:VITE_GUARDIAN_API_URL
$env:VITE_GUARDIAN_API_URL = $ServerUrl
$buildConsole = & npm run build 2>&1
$env:VITE_GUARDIAN_API_URL = $previousViteApiUrl
if ($LASTEXITCODE -ne 0) {
    Write-Host "[AVISO] Falha no build de produção do Console. Usando modo Dev Vite..." -ForegroundColor Yellow
} else {
    Write-Host "       Guardian Console Web verificado e compilado." -ForegroundColor Green
}

# 4. Iniciar Servidor Mestre e Dashboard Web
Write-Host "[4/5] Subindo Servidor API (Porta $ApiPort) e Dashboard Console (Porta $ConsolePort)..." -ForegroundColor Yellow
$PreviousPort = $env:PORT
$env:PORT = $ApiPort
Start-Process node -ArgumentList "`"$ScriptDir\guardian-core\dist\index.js`"" -WorkingDirectory "$ScriptDir\guardian-core" -WindowStyle Hidden
$env:PORT = $PreviousPort
$env:VITE_GUARDIAN_API_URL = $ServerUrl
Start-Process cmd.exe -ArgumentList "/c", "npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", $ConsolePort -WorkingDirectory "$ScriptDir\guardian-console" -WindowStyle Hidden

# 5. Iniciar Agente EDR Local (Rust Agent para Windows)
Write-Host "[5/5] Iniciando Agente EDR Local (Rust Windows Agent)..." -ForegroundColor Yellow
$ReleaseAgent = "$ScriptDir\guardian-agent\target\release\guardian-agent.exe"
$DebugAgent = "$ScriptDir\guardian-agent\target\debug\guardian-agent.exe"

if (Test-Path $ReleaseAgent) {
    Start-Process $ReleaseAgent -ArgumentList "`"$ServerUrl`"" -WorkingDirectory "$ScriptDir\guardian-agent" -WindowStyle Hidden
    Write-Host "       Agente EDR Windows (Release) iniciado." -ForegroundColor Green
} elseif (Test-Path $DebugAgent) {
    Start-Process $DebugAgent -ArgumentList "`"$ServerUrl`"" -WorkingDirectory "$ScriptDir\guardian-agent" -WindowStyle Hidden
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
        $res = Invoke-WebRequest -Uri "http://localhost:$ApiPort/api/v1/health" -TimeoutSec 2 -ErrorAction Stop
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
    Write-Host "       Servidor API respondendo com sucesso na porta $ApiPort!" -ForegroundColor Green
} else {
    Write-Host "       [AVISO] Servidor ainda está inicializando..." -ForegroundColor Yellow
}

# Abrir o Dashboard no Navegador Padrão
Start-Process "http://localhost:$ConsolePort"

$dbPath = "$ScriptDir\guardian-core\guardian.db"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " ✅ SISTEMA MESTRE GUARDIAN EDR & NDR ATIVADO E RODANDO!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " 🌐 Dashboard Web:         http://localhost:$ConsolePort" -ForegroundColor Cyan
Write-Host " 🌐 Dashboard Rede Local:   http://${LocalIP}:$ConsolePort" -ForegroundColor Cyan
Write-Host " 🛡️ API Core Server:      $ServerUrl" -ForegroundColor Cyan
Write-Host " 🗄️ Banco de Dados:        SQLite ($dbPath)" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host " 📱 COMANDO DE INSTALAÇÃO AUTOMÁTICA NO ANDROID (TERMUX):" -ForegroundColor Yellow
Write-Host "    pkg install -y curl bash && curl -sSL $ServerUrl/android.sh | bash" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

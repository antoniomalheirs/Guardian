# ==============================================================================
# 🛡️ GUARDIAN EDR & NDR PLATFORM — MASTER SYSTEM LAUNCHER (v11.0.0)
# ==============================================================================
# Script de Inicialização Automática da Máquina Mestre e Subsistemas
# ==============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " 🛡️ INICIALIZANDO GUARDIAN EDR & NDR MASTER SYSTEM (SUBNET 192.168.50.X)" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Finalizar processos anteriores em execução
Write-Host "[1/4] Encerrando instâncias antigas em execução..." -ForegroundColor Yellow
Get-Process -Name "node", "guardian-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 2. Compilar Servidor Mestre e Painel Web
Write-Host "[2/4] Compilando Guardian Core API e Dashboard Console..." -ForegroundColor Yellow
Set-Location "$ScriptDir\guardian-core"
cmd.exe /c "npm run build" | Out-Null

Set-Location "$ScriptDir\guardian-console"
cmd.exe /c "npm run build" | Out-Null

# 3. Iniciar Servidores Mestre (Porta 4000 & 4001)
Write-Host "[3/4] Iniciando Servidor Mestre (Porta 4000) e Dashboard (Porta 4001)..." -ForegroundColor Yellow
Start-Process node -ArgumentList "$ScriptDir\guardian-core\dist\index.js" -WorkingDirectory "$ScriptDir\guardian-core" -WindowStyle Hidden
Start-Process cmd.exe -ArgumentList "/c npm --prefix `"$ScriptDir\guardian-console`" run dev" -WorkingDirectory "$ScriptDir\guardian-console" -WindowStyle Hidden

# 4. Iniciar Agente EDR Local (Rust Agent)
Write-Host "[4/4] Iniciando Agente EDR Local (Rust Agent)..." -ForegroundColor Yellow
$ReleaseAgent = "$ScriptDir\guardian-agent\target\release\guardian-agent.exe"
$DebugAgent = "$ScriptDir\guardian-agent\target\debug\guardian-agent.exe"

if (Test-Path $ReleaseAgent) {
    Start-Process $ReleaseAgent -WorkingDirectory "$ScriptDir\guardian-agent" -WindowStyle Hidden
} elseif (Test-Path $DebugAgent) {
    Start-Process $DebugAgent -WorkingDirectory "$ScriptDir\guardian-agent" -WindowStyle Hidden
}

Start-Sleep -Seconds 3

# Abrir o Dashboard no Navegador Padrão
Start-Process "http://localhost:4001"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " ✅ SISTEMA MESTRE DO GUARDIAN ATIVADO E RODANDO COM SUCESSO!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " 🌐 Dashboard Web:    http://localhost:4001" -ForegroundColor Cyan
Write-Host " 🛡️ API Server:       http://localhost:4000" -ForegroundColor Cyan
Write-Host " 📱 Download Android: http://192.168.50.140:4000/download/agent.py" -ForegroundColor Yellow
Write-Host " 🗄️ Banco SQL:       SQLite ($ScriptDir\guardian-core\guardian.db)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""

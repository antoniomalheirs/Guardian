# ==============================================================================
# 🛡️ GUARDIAN EDR — MONITOR/AGENT INSTALLER (Windows)
# ==============================================================================
param(
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl = $env:GUARDIAN_SERVER_URL
)

if (-not $ServerUrl) {
    Write-Host "Uso: .\install-monitor.ps1 -ServerUrl http://IP_DA_MAQUINA_MESTRE:4000" -ForegroundColor Red
    exit 1
}
$ServerUrl = $ServerUrl.TrimEnd('/')
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$AgentDir = Join-Path $ScriptDir "guardian-agent"
$ReleaseAgent = Join-Path $AgentDir "target\release\guardian-agent.exe"
$DebugAgent = Join-Path $AgentDir "target\debug\guardian-agent.exe"
$InstallDir = Join-Path $env:USERPROFILE ".guardian"
$InstalledAgent = Join-Path $InstallDir "guardian-agent.exe"
$ServerFile = Join-Path $InstallDir "server_url.txt"
$LogFile = Join-Path $InstallDir "guardian-agent.log"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if (-not (Test-Path $ReleaseAgent) -and -not (Test-Path $DebugAgent)) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Host "Cargo/Rust não encontrado. Instale Rust ou copie um guardian-agent.exe compilado." -ForegroundColor Red
        exit 1
    }
    Push-Location $AgentDir
    cargo build --release
    if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }
    Pop-Location
}

$SourceAgent = if (Test-Path $ReleaseAgent) { $ReleaseAgent } else { $DebugAgent }
Copy-Item $SourceAgent $InstalledAgent -Force
Set-Content -Path $ServerFile -Value $ServerUrl -Encoding UTF8

Get-Process -Name "guardian-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Process $InstalledAgent -ArgumentList "`"$ServerUrl`"" -WorkingDirectory $InstallDir -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err"

$Control = Join-Path $InstallDir "guardian-monitor.ps1"
@'
param([string]$Command = "status")
$InstallDir = Join-Path $env:USERPROFILE ".guardian"
$Agent = Join-Path $InstallDir "guardian-agent.exe"
$ServerUrl = (Get-Content (Join-Path $InstallDir "server_url.txt") -ErrorAction SilentlyContinue | Select-Object -First 1)
$LogFile = Join-Path $InstallDir "guardian-agent.log"
switch ($Command) {
  "start" { Start-Process $Agent -ArgumentList "`"$ServerUrl`"" -WorkingDirectory $InstallDir -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError "$LogFile.err"; "Guardian monitor iniciado." }
  "stop" { Get-Process -Name "guardian-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; "Guardian monitor parado." }
  "restart" { & $PSCommandPath stop; Start-Sleep -Seconds 1; & $PSCommandPath start }
  "status" { if (Get-Process -Name "guardian-agent" -ErrorAction SilentlyContinue) { "Ativo" } else { "Inativo" } }
  "logs" { Get-Content $LogFile -Tail 80 -Wait }
  default { "Uso: guardian-monitor.ps1 {start|stop|restart|status|logs}" }
}
'@ | Set-Content -Path $Control -Encoding UTF8

Write-Host "✅ Monitor Windows instalado e iniciado contra $ServerUrl" -ForegroundColor Green
Write-Host "Controle: powershell -ExecutionPolicy Bypass -File $Control status" -ForegroundColor Cyan

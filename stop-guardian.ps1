# ==============================================================================
# 🛡️ GUARDIAN EDR & NDR PLATFORM — MASTER SYSTEM SHUTDOWN
# ==============================================================================

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host " 🛑 ENCERRANDO SISTEMA MESTRE DO GUARDIAN E SUBSISTEMAS" -ForegroundColor Red
Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host ""

Get-Process -Name "node", "guardian-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "✅ Todos os servicos (Core API 4000, Dashboard 4001, Agentes Locais) foram encerrados!" -ForegroundColor Green
Write-Host ""
Start-Sleep -Seconds 2

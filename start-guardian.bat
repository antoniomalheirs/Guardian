@echo off
title Guardian EDR ^& NDR Master System Launcher v12.0
color 0A
cls
echo ======================================================================
echo  GUARDIAN EDR ^& NDR MASTER SYSTEM (SUBNET DISCOVERY)
echo ======================================================================
echo.

where pwsh >nul 2>nul
if %ERRORLEVEL% equ 0 (
    pwsh -ExecutionPolicy Bypass -File "%~dp0start-guardian.ps1"
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0start-guardian.ps1"
)

pause

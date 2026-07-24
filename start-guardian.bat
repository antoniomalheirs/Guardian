@echo off
title Guardian Master System Launcher
color 0A
cls
echo ======================================================================
echo  GUARDIAN EDR ^& NDR MASTER SYSTEM (SUBNET 192.168.50.X)
echo ======================================================================
echo.

powershell -ExecutionPolicy Bypass -File "%~dp0start-guardian.ps1"
pause

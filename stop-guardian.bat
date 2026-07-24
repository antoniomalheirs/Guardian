@echo off
title Guardian Master System Shutdown
color 0C
cls
powershell -ExecutionPolicy Bypass -File "%~dp0stop-guardian.ps1"
pause

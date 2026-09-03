@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-local-8080.ps1"
if errorlevel 1 (
  echo.
  echo Startup failed. Review the message above.
  pause
)


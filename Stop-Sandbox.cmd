@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Stop-Sandbox.ps1"
if errorlevel 1 pause

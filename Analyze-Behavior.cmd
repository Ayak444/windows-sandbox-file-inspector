@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-Behavior.ps1"
if errorlevel 1 pause

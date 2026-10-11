@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Observe-Behavior.ps1
if errorlevel 1 pause

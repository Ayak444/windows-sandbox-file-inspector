@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Inspect-Files.ps1
if errorlevel 1 pause

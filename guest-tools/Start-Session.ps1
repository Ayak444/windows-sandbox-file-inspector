Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or $PSScriptRoot -ne 'C:\SandboxTools') {
    throw 'Run this script only inside Windows Sandbox, never on the host.'
}
$desktop = [Environment]::GetFolderPath('Desktop')
$samples = Join-Path $desktop 'Samples'
$analysis = Join-Path $desktop 'Analysis'
New-Item -ItemType Directory -Path $samples, $analysis -Force | Out-Null
$failureCode = 21
try {
# Disable Explorer previews and show complete names before exposing samples.
$advanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$failureCode = 211
if (!(Test-Path -LiteralPath $advanced)) { New-Item -Path $advanced -Force | Out-Null }
$failureCode = 212
Set-ItemProperty -Path $advanced -Name HideFileExt -Value 0
$failureCode = 213
Set-ItemProperty -Path $advanced -Name ShowPreviewHandlers -Value 0
$failureCode = 214
Set-ItemProperty -Path $advanced -Name IconsOnly -Value 1
$failureCode = 22
foreach ($item in Get-ChildItem -LiteralPath 'C:\Incoming' -Force) {
    Copy-Item -LiteralPath $item.FullName -Destination $samples -Recurse -Force
}
$failureCode = 23
Copy-Item -LiteralPath 'C:\SandboxTools\HOW-TO.txt' -Destination $desktop
$failureCode = 24
@'
@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\SandboxTools\Capture-State.ps1 -Label after
pause
'@ | Set-Content -LiteralPath (Join-Path $desktop 'Capture-After.cmd') -Encoding ASCII
Copy-Item -LiteralPath 'C:\SandboxTools\Check-Files.cmd' -Destination (Join-Path $desktop 'Check-Files.cmd') -Force
Copy-Item -LiteralPath 'C:\SandboxTools\Analyze-Behavior.cmd' -Destination (Join-Path $desktop 'Analyze-Behavior.cmd') -Force
$failureCode = 25
& 'C:\SandboxTools\Capture-State.ps1' -Label before
$failureCode = 26
Start-Process explorer.exe -ArgumentList ('"' + $samples + '"')
}
catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $analysis 'bootstrap-error.txt') -Encoding UTF8
    exit $failureCode
}
